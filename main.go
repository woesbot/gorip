package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// NOTE:
// Hash algo: cmd/internal/notsha256

const (
	MAX_FILE_SIZE      int64  = 2e9              // ~2GB
	DEFAULT_CHUNK_SIZE uint64 = 1024 * 1024 * 16 // 16MB
)

var (
	flagTargetBin string

	flagChunkSize        uint64 = DEFAULT_CHUNK_SIZE
	flagExtractCandidate bool   = false
	flagGenerateManifest bool   = false
	flagGenerateFSTree   bool   = false
	flagVerbose          bool   = false
)

func init() {
	const (
		usage string = `Usage: ./gorip [options] <binary>

Options:
  -c, --chunk-size <size>
      Set chunk size in bytes (default: 16777216 (16 MB))

  -e, --extract
      Extract candidates from the binary (default: false)

  -m, --manifest
      Generate a candidate manifest for the binary (default: false)

  -t, --tree
	  Generate a file tree for the binary (default: false)

  -v, --verbose
	  Increase verbosity

Examples:
  ./gorip -c 1048576 -e ./path/to/binary
  ./gorip --manifest --tree ./path/to/binary`
	)

	fs := flag.NewFlagSet("", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stdout, usage)
	}

	fs.BoolVar(&flagExtractCandidate, "extract", false, "")
	fs.BoolVar(&flagExtractCandidate, "e", false, "")

	fs.BoolVar(&flagGenerateManifest, "manifest", false, "")
	fs.BoolVar(&flagGenerateManifest, "m", false, "")

	fs.BoolVar(&flagGenerateFSTree, "tree", false, "")
	fs.BoolVar(&flagGenerateFSTree, "t", false, "")

	fs.BoolVar(&flagVerbose, "verbose", false, "")
	fs.BoolVar(&flagVerbose, "v", false, "")

	fs.Uint64Var(&flagChunkSize, "chunk-size", DEFAULT_CHUNK_SIZE, "")
	fs.Uint64Var(&flagChunkSize, "c", DEFAULT_CHUNK_SIZE, "")

	fs.Parse(os.Args[1:])
	args := fs.Args()

	if len(args) == 0 {
		fs.Usage()
		os.Exit(1)
	}
	flagTargetBin = args[0]
	flagChunkSize += flagChunkSize % 2 // chunk size should be a multiple of 2

	// fmt.Printf("CS: %d EC: %v GM: %v FST: %v V: %v\n", flagChunkSize, flagExtractCandidate, flagGenerateManifest, flagGenerateFSTree, flagVerbose)
}

func main() {
	f, err := os.Open(flagTargetBin)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	x, err := DetectExeFormat(f)
	if err != nil {
		panic(err)
	}

	fmt.Println("[+] Detected format:", x.FormatName())
	sd, err := x.Rodata()
	if err != nil {
		panic(err)
	}

	if flagVerbose {
		PrintSectionInfo(sd)
	}

	start := time.Now()
	candidates := findCandidates(sd)
	elapsed := time.Since(start)

	// there are probably better ways of measuring this
	ops := sd.FileSize / uint64(elapsed.Milliseconds())
	fmt.Printf("[+] Candidate(s) found: %d. Took %v (~%d B/ms)\n", len(candidates), elapsed, ops)

	if flagExtractCandidate {
		extractCandidates(candidates)
	}
	if flagGenerateManifest {
		generateManifest(sd, candidates, f.Name())
	}
	if flagGenerateFSTree {
		generateFileTree(candidates, f.Name())
	}
}

func generateManifest(sd *SectionData, candidates []*FSCandidate, name string) {
	var writer io.Writer

	if len(name) > 0 {
		fname := fmt.Sprintf("%s.manifest", name)
		fname = filepath.Base(fname)

		m, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			panic(err)
		}

		defer m.Close()
		writer = m
	} else {
		writer = os.Stdout
	}

	for _, candidate := range candidates {
		fmt.Fprintf(writer, "Candidate VA: %#x FO: %#x\n", candidate.Addr, TL_FileOffset(sd, candidate.Addr))
		fmt.Fprintf(writer, "%3s %9s %-32s %-11s %s\n", "", "Size", "Notsha256", "File offset", "Name")

		size := 0
		d := 0

		for i := uint64(0); i < candidate.EntryCount; i++ {
			e := candidate.Entry(i)

			offset := TL_FileOffset(candidate.sd, candidate.Addr) + candidate.EntrySize()*i
			fmt.Fprintf(writer, "%-3d %9d %-32x %#-11x %s\n", i, e.Data.Size, e.Hash, offset, e.Name)

			size += int(e.Data.Size)
			if e.IsDir {
				d += 1
			}
		}
		fmt.Fprintf(writer, "[+] Total Size: %d (bytes) %d files %d folders\n", size, int(candidate.EntryCount)-d, d)
		fmt.Fprintln(writer)
	}
}

func generateFileTree(candidates []*FSCandidate, name string) {
	var writer io.Writer

	if len(name) > 0 {
		fname := fmt.Sprintf("%s.tree", name)
		fname = filepath.Base(fname)

		m, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			panic(err)
		}

		defer m.Close()
		writer = m
	} else {
		writer = os.Stdout
	}

	tree := NewFileTree()
	for _, candidate := range candidates {
		for _, e := range candidate.Entries() {
			tree.Insert(e)
		}
	}

	PrintTreeSorted(tree.Root, "", writer)
}

func extractCandidates(candidates []*FSCandidate) {
	for _, candidate := range candidates {
		for _, entry := range candidate.Entries() {
			if entry.IsDir {
				os.Mkdir(entry.Name, 0755)
			} else {
				// TODO: Should probably change this to an iterator so significantly large
				// files are not loaded completely into memory.
				data, err := entry.Read()
				if err != nil {
					panic(err)
				}

				f, err := os.OpenFile(entry.Name, os.O_RDWR|os.O_CREATE, 0755)
				if err != nil {
					panic(err)
				}

				f.Write(data)
				f.Close()
			}
		}
	}
}
