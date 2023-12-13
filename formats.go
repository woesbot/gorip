package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"debug/elf"
	"debug/macho"
	"debug/pe"
)

var (
	// unrecognized file format
	errUnrecognizedFormat = "unrecognized file format"
	// section \"%s\" does not exist
	errSectionNonexistent = "section \"%s\" does not exist"
)

func DetectExeFormat(r io.ReaderAt) (exe, error) {
	ident := make([]byte, 16)
	if n, err := r.ReadAt(ident, 0); n < len(ident) || err != nil {
		return nil, fmt.Errorf(errUnrecognizedFormat)
	}

	fmt.Printf("[+] Ident: %x\n", ident)

	switch {
	case bytes.HasPrefix(ident, []byte("MZ")):
		f, err := pe.NewFile(r)
		if err != nil {
			return nil, err
		}
		return &exePE{f}, nil

	case bytes.HasPrefix(ident, []byte("\x7fELF")):
		f, err := elf.NewFile(r)
		if err != nil {
			panic(err)
		}
		return &exeELF{f}, nil

	case bytes.HasPrefix(ident, []byte("\xfe\xed\xfa")) || bytes.HasPrefix(ident[1:], []byte("\xfa\xed\xfe")):
		// MACHO32BE = 0xfeedfa_ce | MACHO32LE = 0xce_faedfe
		// MACHO64BE = 0xfeedfa_cf | MACHO64LE = 0xcf_faedfe
		f, err := macho.NewFile(r)
		if err != nil {
			return nil, err
		}
		return &exeMACHO{f}, nil
	}

	return nil, fmt.Errorf(errUnrecognizedFormat)
}

type exe interface {
	FormatName() string
	Rodata() (*SectionData, error)
	SectionData(x string) (*SectionData, error)
}

type exePE struct {
	f *pe.File
}
type exeELF struct {
	f *elf.File
}
type exeMACHO struct {
	f *macho.File
}

func (x *exeELF) FormatName() string   { return "ELF" }
func (x *exePE) FormatName() string    { return "PE" }
func (x *exeMACHO) FormatName() string { return "MACHO" }

func (x *exeELF) Rodata() (*SectionData, error)   { return x.SectionData(".rodata") }
func (x *exePE) Rodata() (*SectionData, error)    { return x.SectionData(".rdata") }
func (x *exeMACHO) Rodata() (*SectionData, error) { return x.SectionData("__rodata") }

func (x *exePE) imageBase() uint64 {
	switch oh := x.f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		return oh.ImageBase
	}

	return 0
}

func (x *exePE) SectionData(name string) (*SectionData, error) {
	s := x.f.Section(name)
	if s == nil {
		return nil, fmt.Errorf(errSectionNonexistent, name)
	}

	var psize int
	switch x.f.FileHeader.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		psize = 4
	case pe.IMAGE_FILE_MACHINE_ARM:
		psize = 4
	case pe.IMAGE_FILE_MACHINE_ARM64:
		psize = 8
	case pe.IMAGE_FILE_MACHINE_AMD64:
		psize = 8
	default:
		panic(fmt.Errorf("unsupported PE architecture"))
	}

	d := SectionData{
		Name: name,

		VirtualAddr: uint64(s.VirtualAddress),
		VirtualSize: uint64(s.VirtualSize),
		BaseAddr:    x.imageBase(),

		FileOffset: uint64(s.Offset),
		FileSize:   uint64(s.Size),
		Order:      binary.LittleEndian,

		Data:  s.Open(),
		Ptrsz: psize,
	}

	return &d, nil
}

func (x *exeELF) imageBase() uint64 {
	return 0
	// usually 0x8048000 (32-bit) 0x400000 (64-bit)
	// for _, prog := range x.f.Progs {
	//  // Assume that the virtual address of the first PT_LOAD header is the
	// 	// base address.
	// 	if prog.Type == elf.PT_LOAD {
	// 		return prog.Vaddr
	// 	}
	// }
}

func (x *exeELF) SectionData(name string) (*SectionData, error) {
	s := x.f.Section(name)
	if s == nil {
		return nil, fmt.Errorf(errSectionNonexistent, name)
	}

	var psize int
	switch x.f.Class {
	case elf.ELFCLASS32:
		psize = 4
	case elf.ELFCLASS64:
		psize = 8
	default:
		panic(fmt.Errorf("unsupported ELF architecture"))
	}

	d := SectionData{
		Name: name,

		VirtualAddr: s.Addr,
		VirtualSize: s.Size,
		BaseAddr:    x.imageBase(),

		// Use s.Size here instead of s.Filesize because if a section is
		// compressed, s.Filesize will return the compressed size.
		FileSize:   s.Size,
		FileOffset: s.Offset,

		Order: x.f.ByteOrder,

		Ptrsz: psize,
		Data:  s.Open(),
	}

	return &d, nil
}

func (x *exeMACHO) SectionData(name string) (*SectionData, error) {
	s := x.f.Section(name)
	if s == nil {
		return nil, fmt.Errorf(errSectionNonexistent, name)
	}

	d := SectionData{
		Name: name,

		VirtualAddr: s.Addr,
		VirtualSize: s.Size,
		BaseAddr:    0,

		FileOffset: uint64(s.Offset),
		FileSize:   s.Size,

		Order: x.f.ByteOrder,
		// Apple ended support for 32-bit applications in 2019 with the release of
		// Catalina (v10.15). The embed package was released (15-02-2021 v1.16), so
		// all go binaries compiled for darwin should be 64-bit.
		Ptrsz: 8,
		Data:  s.Open(),
	}

	return &d, nil
}
