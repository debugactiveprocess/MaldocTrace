package cfbtest

import (
	"encoding/binary"
	"sort"
)

// CompressOVBA encodes data in the MS-OVBA compressed container format
// using only literal tokens (and raw 4096-byte chunks), which every
// decompressor accepts.
func CompressOVBA(data []byte) []byte {
	out := []byte{0x01}
	for len(data) > 0 {
		if len(data) > 3640 {
			// Raw chunk: exactly 4096 bytes, size field 4095.
			chunk := make([]byte, 4096)
			n := copy(chunk, data)
			out = binary.LittleEndian.AppendUint16(out, 0x3000|4095)
			out = append(out, chunk...)
			data = data[n:]
			continue
		}
		var body []byte
		for i := 0; i < len(data); i += 8 {
			body = append(body, 0x00)
			end := min(i+8, len(data))
			body = append(body, data[i:end]...)
		}
		out = binary.LittleEndian.AppendUint16(out, 0x8000|0x3000|uint16(len(body)+2-3))
		out = append(out, body...)
		data = nil
	}
	return out
}

func rec(id uint16, data []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, id)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
	return append(b, data...)
}

func u16le(s string) []byte {
	var b []byte
	for _, r := range s {
		b = binary.LittleEndian.AppendUint16(b, uint16(r))
	}
	return b
}

// VBAProject returns the streams of a VBA project storage (dir, module
// streams, _VBA_PROJECT and PROJECT) under prefix ("" or "Macros/"), with
// one procedural module per entry of modules (name -> source).
func VBAProject(prefix string, modules map[string]string) []Stream {
	var names []string
	for n := range modules {
		names = append(names, n)
	}
	sort.Strings(names)
	u32 := func(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
	u16 := func(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
	var dir []byte
	dir = append(dir, rec(0x0001, u32(1))...)     // SYSKIND win32
	dir = append(dir, rec(0x0002, u32(0x409))...) // LCID
	dir = append(dir, rec(0x0014, u32(0x409))...) // LCIDINVOKE
	dir = append(dir, rec(0x0003, u16(1252))...)  // CODEPAGE
	dir = append(dir, rec(0x0004, []byte("Project"))...)
	dir = append(dir, rec(0x0005, nil)...)
	dir = append(dir, rec(0x0040, nil)...)
	dir = append(dir, rec(0x0006, nil)...)
	dir = append(dir, rec(0x003D, nil)...)
	dir = append(dir, rec(0x0007, u32(0))...)
	dir = append(dir, rec(0x0008, u32(0))...)
	// PROJECTVERSION: id, reserved=4, major, minor
	dir = binary.LittleEndian.AppendUint16(dir, 0x0009)
	dir = append(dir, u32(4)...)
	dir = append(dir, u32(1)...)
	dir = append(dir, u16(1)...)
	dir = append(dir, rec(0x000C, nil)...)
	dir = append(dir, rec(0x003C, nil)...)
	dir = append(dir, rec(0x000F, u16(uint16(len(names))))...)
	dir = append(dir, rec(0x0013, u16(0xFFFF))...)
	var streams []Stream
	for _, n := range names {
		dir = append(dir, rec(0x0019, []byte(n))...)
		dir = append(dir, rec(0x0047, u16le(n))...)
		dir = append(dir, rec(0x001A, []byte(n))...)
		dir = append(dir, rec(0x0032, u16le(n))...)
		dir = append(dir, rec(0x001C, nil)...)
		dir = append(dir, rec(0x0048, nil)...)
		dir = append(dir, rec(0x0031, u32(0))...)
		dir = append(dir, rec(0x001E, u32(0))...)
		dir = append(dir, rec(0x002C, u16(0xFFFF))...)
		dir = append(dir, rec(0x0021, nil)...)
		dir = append(dir, rec(0x002B, nil)...)
		streams = append(streams, Stream{Name: prefix + "VBA/" + n, Data: CompressOVBA([]byte(modules[n]))})
	}
	dir = append(dir, rec(0x0010, nil)...)
	streams = append(streams,
		Stream{Name: prefix + "VBA/dir", Data: CompressOVBA(dir)},
		Stream{Name: prefix + "VBA/_VBA_PROJECT", Data: []byte{0xCC, 0x61, 0xFF, 0xFF, 0x00, 0x00, 0x00}},
		Stream{Name: prefix + "PROJECT", Data: []byte("ID=\"{00000000-0000-0000-0000-000000000000}\"\r\nModule=" + names[0] + "\r\nName=\"Project\"\r\n")},
	)
	return streams
}
