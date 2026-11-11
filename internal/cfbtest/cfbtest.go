// Package cfbtest builds minimal OLE compound files for tests. It writes
// flat containers (streams directly under the root, no storages) with
// 512-byte sectors; streams are padded to the mini-stream cutoff so every
// stream lives in the regular FAT.
package cfbtest

import (
	"encoding/binary"
	"unicode/utf16"
)

const (
	sector    = 512
	endChain  = 0xFFFFFFFE
	freeSect  = 0xFFFFFFFF
	fatSect   = 0xFFFFFFFD
	noStream  = 0xFFFFFFFF
	miniLimit = 4096
)

// Stream is a named stream of the container.
type Stream struct {
	Name string
	Data []byte
}

// Build returns a CFB file containing the given streams.
func Build(streams ...Stream) []byte {
	type placed struct {
		start, sectors int
		size           int
	}
	var body []byte
	var pl []placed
	next := 0
	for _, s := range streams {
		data := s.Data
		if len(data) < miniLimit {
			pad := make([]byte, miniLimit)
			copy(pad, data)
			data = pad
		}
		n := (len(data) + sector - 1) / sector
		buf := make([]byte, n*sector)
		copy(buf, data)
		body = append(body, buf...)
		pl = append(pl, placed{start: next, sectors: n, size: len(data)})
		next += n
	}
	// Directory: root + one entry per stream, 4 entries per sector.
	entries := 1 + len(streams)
	dirSectors := (entries + 3) / 4
	dirStart := next
	dir := make([]byte, dirSectors*sector)
	writeEntry(dir[0:], "Root Entry", 5, -1, -1, int32(boolInt(len(streams) > 0)), endChain, 0)
	for i, s := range streams {
		right := int32(i + 2)
		if i == len(streams)-1 {
			right = -1
		}
		writeEntry(dir[(i+1)*128:], s.Name, 2, -1, right, -1, uint32(pl[i].start), uint64(pl[i].size))
	}
	for i := entries; i < dirSectors*4; i++ {
		writeEntry(dir[i*128:], "", 0, -1, -1, -1, 0, 0)
	}
	body = append(body, dir...)
	next += dirSectors
	// FAT: chains for streams and directory, plus the FAT sectors themselves.
	total := next
	fatSectors := 1
	for (total+fatSectors)*4 > fatSectors*sector {
		fatSectors++
	}
	fat := make([]uint32, fatSectors*sector/4)
	for i := range fat {
		fat[i] = freeSect
	}
	chain := func(start, n int) {
		for k := 0; k < n; k++ {
			if k == n-1 {
				fat[start+k] = endChain
			} else {
				fat[start+k] = uint32(start + k + 1)
			}
		}
	}
	for _, p := range pl {
		chain(p.start, p.sectors)
	}
	chain(dirStart, dirSectors)
	fatStart := next
	for k := 0; k < fatSectors; k++ {
		fat[fatStart+k] = fatSect
	}
	fatBytes := make([]byte, len(fat)*4)
	for i, v := range fat {
		binary.LittleEndian.PutUint32(fatBytes[i*4:], v)
	}
	body = append(body, fatBytes...)

	hdr := make([]byte, sector)
	copy(hdr, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(hdr[0x18:], 0x3E)
	binary.LittleEndian.PutUint16(hdr[0x1A:], 3)
	binary.LittleEndian.PutUint16(hdr[0x1C:], 0xFFFE)
	binary.LittleEndian.PutUint16(hdr[0x1E:], 9)
	binary.LittleEndian.PutUint16(hdr[0x20:], 6)
	binary.LittleEndian.PutUint32(hdr[0x2C:], uint32(fatSectors))
	binary.LittleEndian.PutUint32(hdr[0x30:], uint32(dirStart))
	binary.LittleEndian.PutUint32(hdr[0x38:], miniLimit)
	binary.LittleEndian.PutUint32(hdr[0x3C:], endChain)
	binary.LittleEndian.PutUint32(hdr[0x44:], endChain)
	for i := 0; i < 109; i++ {
		v := uint32(freeSect)
		if i < fatSectors {
			v = uint32(fatStart + i)
		}
		binary.LittleEndian.PutUint32(hdr[0x4C+i*4:], v)
	}
	return append(hdr, body...)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return -1
}

func writeEntry(b []byte, name string, typ byte, left, right, child int32, start uint32, size uint64) {
	u := utf16.Encode([]rune(name))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	if name != "" {
		binary.LittleEndian.PutUint16(b[0x40:], uint16(len(u)*2+2))
	}
	b[0x42] = typ
	b[0x43] = 1
	binary.LittleEndian.PutUint32(b[0x44:], uint32(left))
	binary.LittleEndian.PutUint32(b[0x48:], uint32(right))
	binary.LittleEndian.PutUint32(b[0x4C:], uint32(child))
	if typ == 0 {
		binary.LittleEndian.PutUint32(b[0x44:], noStream)
		binary.LittleEndian.PutUint32(b[0x48:], noStream)
		binary.LittleEndian.PutUint32(b[0x4C:], noStream)
	}
	binary.LittleEndian.PutUint32(b[0x74:], start)
	binary.LittleEndian.PutUint64(b[0x78:], size)
}

// Record encodes one BIFF record.
func Record(typ uint16, data []byte) []byte {
	b := make([]byte, 4, 4+len(data))
	binary.LittleEndian.PutUint16(b, typ)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(data)))
	return append(b, data...)
}
