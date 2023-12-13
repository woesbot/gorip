package main

import (
	"fmt"
	"io"
)

func findCandidates(sd *SectionData) []*FSCandidate {
	var scan func(sd *SectionData) []*FSCandidate
	var t string

	if sd.FileSize >= uint64(flagChunkSize) {
		t = "chunked"
		scan = findCandidatesChunked
	} else {
		t = "un-chunked"
		scan = findCandidatesUnChunked
	}

	if flagVerbose {
		fmt.Printf("[~] Using %s scan\n", t)
	}

	return scan(sd)
}

func candidateScan(sd *SectionData, buffer []byte, chunkOffset uint64, v bool) []*FSCandidate {
	// reference: /src/cmd/compile/internal/staticdata/embed.go#L141-L143
	patternLength := sd.Ptrsz * 3
	buflen := len(buffer)

	candidates := []*FSCandidate{}

	// should be safe to increment by pointer size due to section alignment right?
	for i := 0; i < buflen-patternLength; i += sd.Ptrsz {
		addr := sd.ReadptrFrom(buffer[i : i+sd.Ptrsz])
		s1 := sd.ReadptrFrom(buffer[i+sd.Ptrsz : i+sd.Ptrsz*2])
		s2 := sd.ReadptrFrom(buffer[i+sd.Ptrsz*2 : i+sd.Ptrsz*3])

		if s1 != s2 || s1 == 0 || addr == 0 {
			continue // embed.FS does not allow embedding empty directories (s1 > 0)
		}
		if !sd.ContainsAddr(addr) {
			continue // the address should exist within the section address range
		}
		// the parsed address should be positioned +(patternLength) bytes away from
		// the current offset
		curFileOffset := sd.FileOffset + chunkOffset + uint64(i)
		if addr != TL_VirtualAddress(sd, curFileOffset+uint64(patternLength)) {
			continue
		}

		c := &FSCandidate{Addr: addr, EntryCount: s1, RelAddr: TL_SectionOffset(sd, addr), sd: sd}
		// ensure all entries within the candidate are valid (helps eliminate false positives)
		if !isValidCandidate(sd, c) {
			continue
		}
		if flagVerbose {
			fmt.Printf("[~] Found candidate: %#08x File: %#08x (%[2]d) VA: %#08x\n", addr, curFileOffset, TL_VirtualAddress(sd, curFileOffset))
		}
		candidates = append(candidates, c)
	}
	return candidates
}

func findCandidatesUnChunked(sd *SectionData) []*FSCandidate {
	buffer := make([]byte, sd.FileSize)
	br, err := sd.Data.Read(buffer)
	if err != nil {
		panic(err)
	}
	if uint64(br) != sd.FileSize {
		panic(fmt.Errorf("size mismatch between bytes read (%d) and section size (%d)", len(buffer), sd.FileSize))
	}

	return candidateScan(sd, buffer, 0, false)
}

func findCandidatesChunked(sd *SectionData) []*FSCandidate {
	chunk_cap := flagChunkSize
	chunk_buf := make([]byte, chunk_cap)

	candidates := []*FSCandidate{}
	read_total := 0

	for idx := uint64(0); idx < (sd.FileSize/chunk_cap)+1; idx++ {
		read, err := sd.Data.Read(chunk_buf)
		if err != nil && err != io.EOF {
			panic(err)
		}

		read_total += read

		chunk_offset := chunk_cap * idx
		candidates = append(candidates, candidateScan(sd, chunk_buf, chunk_offset, false)...)

		if read == 0 || err == io.EOF {
			break
		}
	}

	if uint64(read_total) != sd.FileSize {
		panic(fmt.Errorf("size mismatch between bytes read (%d) and section size (%d)", read_total, sd.FileSize))
	}

	return candidates
}

// Check if a embed candidate contains valid information relative to the
// section data. This function preserves the current cursor position
func isValidCandidate(s *SectionData, c *FSCandidate) bool {
	defer s.Data.Seek(s.Tell(), io.SeekStart)

	// file entry { name string, data string, hash [16]byte }
	entry_sz := (s.Ptrsz * 4) + 16
	entry := make([]byte, entry_sz)

	offset := TL_SectionOffset(s, c.Addr)
	s.Data.Seek(int64(offset), io.SeekStart)

	for i := uint64(0); i < c.EntryCount; i++ {
		_, err := s.Data.Read(entry)
		if err != nil {
			panic(err)
		}

		name_p := s.ReadptrFrom(entry[0:s.Ptrsz])
		name_l := s.ReadptrFrom(entry[s.Ptrsz : s.Ptrsz*2])
		data_p := s.ReadptrFrom(entry[s.Ptrsz*2 : s.Ptrsz*3])
		data_l := s.ReadptrFrom(entry[s.Ptrsz*3 : s.Ptrsz*4])

		// assumes an entire candidate is invalid if one entry is invalid
		if name_l > 255 || name_l == 0 {
			return false
		}
		if !s.ContainsAddr(name_p) || (!s.ContainsAddr(data_p) && data_p != 0) {
			return false
		}
		if int64(data_l) > int64(MAX_FILE_SIZE) {
			return false
		}
	}

	return true
}
