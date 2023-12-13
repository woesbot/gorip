package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

var (
	// size mismatch between bytes read: (%d) and n: (%d)
	errReadSizeMismatch = "size mismatch between bytes read: (%d) and n: (%d)"
)

type SectionData struct {
	// The choice of uint64 for certain values in this implementation is driven by the need for
	// uniformity across various executable formats. The package debug/elf uses uint64 for specific
	// fields, so using uint64 consistently should ensure compatibility with ELF and other formats.

	Name string

	VirtualAddr uint64
	VirtualSize uint64
	BaseAddr    uint64
	FileOffset  uint64
	FileSize    uint64
	Ptrsz       int

	Order binary.ByteOrder
	Data  io.ReadSeeker
}

// Returns the current cursor position of the section reader
func (s *SectionData) Tell() int64 {
	cur, _ := s.Data.Seek(0, io.SeekCurrent)
	return cur
}

// Reset the cursor position to the start of the section reader
func (s *SectionData) Reset() {
	s.Data.Seek(0, io.SeekStart)
}

// Readptr reads a pointer value from the given byte slice 'b' based on the
// pointer size, and byte order specified in the SectionData.
func (s *SectionData) ReadptrFrom(b []byte) uint64 {
	var reader func(b []byte) uint64

	switch s.Ptrsz {
	default:
		panic(fmt.Errorf("invalid pointer size `%d`", s.Ptrsz))
	case 4:
		reader = func(b []byte) uint64 { return uint64(s.Order.Uint32(b)) }
	case 8:
		reader = s.Order.Uint64
	}

	return reader(b)
}

// ReadAt reads n bytes from the section at a specified offset, using the whence parameter
// as the reference point (e.g., io.SeekStart.) The function also preserves the current section
// cursor position.
func (s *SectionData) ReadAt(offset int64, n uint64, whence int) ([]byte, error) {
	defer s.Data.Seek(s.Tell(), io.SeekStart)
	s.Data.Seek(offset, whence)

	buffer := make([]byte, n)
	read, err := s.Data.Read(buffer)
	if err != nil {
		return nil, err
	}

	if uint64(read) != n {
		return nil, fmt.Errorf(errReadSizeMismatch, read, n)
	}

	return buffer, nil
}

// ContainsAddr checks if a virtual address (vaddr) exists within the address
// boundaries of the current section.
func (s *SectionData) ContainsAddr(vaddr uint64) bool {
	base := s.VirtualAddr + s.BaseAddr
	return vaddr >= base && vaddr <= base+s.VirtualSize
}

// Translate an absolute file offset to a virtual address
func TL_VirtualAddress(s *SectionData, offset uint64) uint64 {
	return offset - s.FileOffset + (s.VirtualAddr + s.BaseAddr)
}

// Translate a virtual address to an absolute file offset
func TL_FileOffset(s *SectionData, vaddr uint64) uint64 {
	return vaddr - (s.VirtualAddr + s.BaseAddr) + s.FileOffset
}

// Translate a virtual address to an offset relative to the section contents
func TL_SectionOffset(s *SectionData, vaddr uint64) uint64 {
	return vaddr - (s.VirtualAddr + s.BaseAddr)
}

func PrintSectionInfo(s *SectionData) {
	fmt.Printf("[~] Section info for \"%s\"\n", s.Name)
	fmt.Printf("  - VA range: %#x-%#x\n", s.VirtualAddr+s.BaseAddr, s.VirtualAddr+s.VirtualSize+s.BaseAddr)
	fmt.Printf("  - File offset: %#x\n", s.FileOffset)
	fmt.Printf("  - File size: %d (%#[1]x)\n", s.FileSize)
	fmt.Printf("  - PTR: %d\n", s.Ptrsz)
}
