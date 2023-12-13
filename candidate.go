package main

import (
	"io"
	"strings"
)

type FSCandidate struct {
	Addr       uint64 // Virtual address
	RelAddr    uint64 // Relative section address
	EntryCount uint64

	sd *SectionData
}

func (f *FSCandidate) EntrySize() uint64 {
	return uint64(f.sd.Ptrsz*4 + 16)
}

// Returns all entries belonging to the candidate
func (f *FSCandidate) Entries() []*FSCEntry {
	entries := []*FSCEntry{}

	for i := uint64(0); i < f.EntryCount; i++ {
		e := f.Entry(i)

		if e != nil {
			entries = append(entries, e)
		}
	}

	return entries
}

// Returns an entry in the range [0, EntryCount-1]
func (c *FSCandidate) Entry(i uint64) *FSCEntry {
	if i >= c.EntryCount {
		return nil
	}
	offset := c.EntrySize() * i
	rsa := offset + c.RelAddr
	// rva := offset + c.Addr

	buf, err := c.sd.ReadAt(int64(rsa), c.EntrySize(), io.SeekStart)
	if err != nil {
		panic(err)
	}
	entry := NewFSCEFromBuffer(buf, c.sd)
	// fmt.Printf("entry:%d (%s) VA: %#x RSA: %#x\n", i, entry.Name, rva, rsa)
	return entry
}

type blob struct {
	Addr uint64
	Size uint64
}

// File System Candidate entry
type FSCEntry struct {
	Name string
	Data blob
	Hash [16]byte

	IsDir bool

	sd *SectionData
}

func (f *FSCEntry) Read() ([]byte, error) {
	return f.sd.ReadAt(int64(f.Data.Addr), f.Data.Size, io.SeekStart)
}

func NewFSCEFromBuffer(b []byte, s *SectionData) *FSCEntry {
	name_p := TL_SectionOffset(s, s.ReadptrFrom(b[0:s.Ptrsz]))
	name_l := s.ReadptrFrom(b[s.Ptrsz : s.Ptrsz*2])

	data_p := TL_SectionOffset(s, s.ReadptrFrom(b[s.Ptrsz*2:s.Ptrsz*3]))
	data_l := s.ReadptrFrom(b[s.Ptrsz*3 : s.Ptrsz*4])

	name_b, err := s.ReadAt(int64(name_p), name_l, io.SeekStart)
	if err != nil {
		panic(err)
	}

	f := FSCEntry{Name: string(name_b), Data: blob{data_p, data_l}, sd: s}
	f.IsDir = strings.HasSuffix(f.Name, "/")
	copy(f.Hash[:], b[s.Ptrsz*4:])

	return &f
}
