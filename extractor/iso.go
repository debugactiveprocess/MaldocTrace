package extractor

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ISO 9660 images arrive as email attachments and inside OneNote sections:
// Windows mounts them on a double click, and before Mark-of-the-Web was
// propagated into them they hid the LNK + DLL pair they carry from it. The
// files of the primary volume are read in memory as archive members.
const (
	isoSector   = 2048
	isoMaxDepth = 8
)

// IsISO reports an ISO 9660 image (volume descriptor "CD001" at sector 16).
func IsISO(data []byte) bool {
	return len(data) >= 16*isoSector+6 && string(data[16*isoSector+1:16*isoSector+6]) == "CD001"
}

func openISO(data []byte, lim *Limits) (*Archive, error) {
	a := &Archive{Kind: "iso"}
	pvd := -1
	for s := 16; s < 32 && (s+1)*isoSector <= len(data); s++ {
		d := data[s*isoSector:]
		if string(d[1:6]) != "CD001" {
			break
		}
		if d[0] == 1 {
			pvd = s * isoSector
			break
		}
		if d[0] == 255 {
			break
		}
	}
	if pvd < 0 {
		return nil, fmt.Errorf("iso: no primary volume descriptor")
	}
	root := data[pvd+156 : pvd+156+34]
	var total int64
	seen := map[uint32]bool{}
	var walk func(extent, size uint32, dir string, depth int)
	walk = func(extent, size uint32, dir string, depth int) {
		if depth > isoMaxDepth || seen[extent] {
			return
		}
		seen[extent] = true
		start := int64(extent) * isoSector
		end := start + int64(size)
		if start < 0 || end > int64(len(data)) || start >= end {
			return
		}
		for p := start; p < end; {
			l := int64(data[p])
			if l == 0 {
				// Records do not cross sectors: skip to the next one.
				p = (p/isoSector + 1) * isoSector
				continue
			}
			if l < 34 || p+l > end {
				return
			}
			rec := data[p : p+l]
			p += l
			nameLen := int(rec[32])
			if 33+nameLen > len(rec) {
				continue
			}
			name := string(rec[33 : 33+nameLen])
			if nameLen == 1 && (name == "\x00" || name == "\x01") {
				continue // "." and ".."
			}
			if i := strings.IndexByte(name, ';'); i >= 0 {
				name = name[:i]
			}
			name = strings.TrimSuffix(name, ".")
			ext := binary.LittleEndian.Uint32(rec[2:])
			sz := binary.LittleEndian.Uint32(rec[10:])
			path := dir + name
			if rec[25]&0x02 != 0 {
				walk(ext, sz, path+"/", depth+1)
				continue
			}
			if len(a.Members) >= maxArchiveMembers {
				a.limit("MaxArchiveMembers", "ISO image has more files than analysed")
				return
			}
			fs, fe := int64(ext)*isoSector, int64(ext)*isoSector+int64(sz)
			if fs < 0 || fe > int64(len(data)) || fs > fe {
				a.Members = append(a.Members, ArchiveMember{Name: path, Err: "file extent outside the image"})
				continue
			}
			if int64(sz) > maxArchiveMemberSize || total+int64(sz) > maxArchiveTotalOutput {
				a.limit("MaxArchiveSize", "ISO file "+path+" exceeds the size limits")
				continue
			}
			total += int64(sz)
			a.Members = append(a.Members, ArchiveMember{Name: path, Data: data[fs:fe]})
		}
	}
	walk(binary.LittleEndian.Uint32(root[2:]), binary.LittleEndian.Uint32(root[10:]), "", 0)
	return a, nil
}
