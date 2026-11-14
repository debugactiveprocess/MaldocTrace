// Package cfbtest builds minimal OLE compound files for tests. Stream names
// may contain "/" to place them in storages ("ObjectPool/_1/\x01Ole").
// Sectors are 512 bytes; streams are padded to the mini-stream cutoff so
// every stream lives in the regular FAT.
package cfbtest

import (
	"encoding/binary"
	"strings"
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

// Build returns a CFB file containing the given streams. Streams shorter
// than 4096 bytes are padded with NULs to that size.
func Build(streams ...Stream) []byte { return build(false, streams) }

// BuildExact is Build without padding: every stream keeps its exact size
// (the mini-stream cutoff is set to 1 so they still live in the FAT). Use
// it for streams whose readers do not tolerate trailing NULs.
func BuildExact(streams ...Stream) []byte { return build(true, streams) }

func build(exact bool, streams []Stream) []byte {
	type placed struct {
		start, sectors int
		size           int
	}
	var body []byte
	var pl []placed
	next := 0
	for _, s := range streams {
		data := s.Data
		if len(data) < miniLimit && !exact {
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
	// Directory: root, one entry per storage named in a stream path
	// ("Storage/Sub/Stream") and one per stream, 4 entries per sector.
	// Siblings are chained through their right links (a valid, if
	// unbalanced, tree).
	type node struct {
		name   string
		typ    byte
		stream int
		kids   []int
	}
	nodes := []*node{{name: "Root Entry", typ: 5, stream: -1}}
	storages := map[string]int{"": 0}
	for i, s := range streams {
		parts := strings.Split(s.Name, "/")
		parent, prefix := 0, ""
		for _, p := range parts[:len(parts)-1] {
			prefix += "/" + p
			id, ok := storages[prefix]
			if !ok {
				id = len(nodes)
				nodes = append(nodes, &node{name: p, typ: 1, stream: -1})
				nodes[parent].kids = append(nodes[parent].kids, id)
				storages[prefix] = id
			}
			parent = id
		}
		id := len(nodes)
		nodes = append(nodes, &node{name: parts[len(parts)-1], typ: 2, stream: i})
		nodes[parent].kids = append(nodes[parent].kids, id)
	}
	right := make([]int32, len(nodes))
	for i := range right {
		right[i] = -1
	}
	for _, n := range nodes {
		for k := 0; k+1 < len(n.kids); k++ {
			right[n.kids[k]] = int32(n.kids[k+1])
		}
	}
	entries := len(nodes)
	dirSectors := (entries + 3) / 4
	dirStart := next
	dir := make([]byte, dirSectors*sector)
	for i, n := range nodes {
		child := int32(-1)
		if len(n.kids) > 0 {
			child = int32(n.kids[0])
		}
		start, size := uint32(endChain), uint64(0)
		if n.typ == 1 {
			start = 0
		}
		if n.stream >= 0 {
			start, size = uint32(pl[n.stream].start), uint64(pl[n.stream].size)
		}
		writeEntry(dir[i*128:], n.name, n.typ, -1, right[i], child, start, size)
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
	if exact {
		binary.LittleEndian.PutUint32(hdr[0x38:], 1)
	} else {
		binary.LittleEndian.PutUint32(hdr[0x38:], miniLimit)
	}
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

// SetRootCLSID returns a copy of a file made by Build or BuildExact whose
// root storage carries the given CLSID (in its on-disk, mixed-endian layout).
func SetRootCLSID(file []byte, clsid [16]byte) []byte {
	out := append([]byte(nil), file...)
	dirStart := int(binary.LittleEndian.Uint32(out[0x30:]))
	copy(out[(dirStart+1)*sector+0x50:], clsid[:])
	return out
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

// BuildV4 builds a version 4 compound file (4096-byte sectors, the layout
// of MSI packages) holding one stream of at least 4096 bytes, so no mini
// stream is needed. The root storage gets the given CLSID.
func BuildV4(name string, data []byte, rootCLSID [16]byte) []byte {
	const ss = 4096
	nData := (len(data) + ss - 1) / ss
	out := make([]byte, ss*(3+nData)) // header, FAT, directory, data
	copy(out, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(out[0x18:], 0x3E)
	binary.LittleEndian.PutUint16(out[0x1A:], 4)
	binary.LittleEndian.PutUint16(out[0x1C:], 0xFFFE)
	binary.LittleEndian.PutUint16(out[0x1E:], 12)
	binary.LittleEndian.PutUint16(out[0x20:], 6)
	binary.LittleEndian.PutUint32(out[0x28:], 1)
	binary.LittleEndian.PutUint32(out[0x2C:], 1)
	binary.LittleEndian.PutUint32(out[0x30:], 1)
	binary.LittleEndian.PutUint32(out[0x38:], 4096)
	binary.LittleEndian.PutUint32(out[0x3C:], 0xFFFFFFFE)
	binary.LittleEndian.PutUint32(out[0x44:], 0xFFFFFFFE)
	for i := 0; i < 109; i++ {
		binary.LittleEndian.PutUint32(out[0x4C+4*i:], 0xFFFFFFFF)
	}
	binary.LittleEndian.PutUint32(out[0x4C:], 0) // FAT in sector 0
	fat := out[ss : 2*ss]
	for i := 0; i < ss/4; i++ {
		binary.LittleEndian.PutUint32(fat[4*i:], 0xFFFFFFFF)
	}
	binary.LittleEndian.PutUint32(fat[0:], 0xFFFFFFFD)
	binary.LittleEndian.PutUint32(fat[4:], 0xFFFFFFFE)
	for i := 0; i < nData; i++ {
		next := uint32(3 + i)
		if i == nData-1 {
			next = 0xFFFFFFFE
		}
		binary.LittleEndian.PutUint32(fat[4*(2+i):], next)
	}
	dir := out[2*ss : 3*ss]
	writeEntry(dir[0:128], "Root Entry", 5, -1, -1, 1, 0xFFFFFFFE, 0)
	copy(dir[0x50:0x60], rootCLSID[:])
	writeEntry(dir[128:256], name, 2, -1, -1, -1, 2, uint64(len(data)))
	for i := 2; i < ss/128; i++ {
		writeEntry(dir[i*128:(i+1)*128], "", 0, 0, 0, 0, 0, 0)
	}
	copy(out[3*ss:], data)
	return out
}
