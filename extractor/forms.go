package extractor

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// FormControl preserves the stream coordinates behind virtual form properties.
// Only decoded declarations are used; no ActiveX code is loaded.
type FormControl struct {
	Module     string            `json:"module"`
	Name       string            `json:"name"`
	Stream     string            `json:"stream"`
	Offset     int               `json:"offset"`
	Class      uint16            `json:"class"`
	SiteID     uint32            `json:"site_id"`
	Properties map[string]string `json:"properties"`
	ObjectSize uint32            `json:"-"`
}

type formReader struct {
	b   []byte
	p   int
	err error
}

func (r *formReader) read(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b)-r.p {
		r.err = fmt.Errorf("truncated forms record at %d (need %d)", r.p, n)
		return nil
	}
	b := r.b[r.p : r.p+n]
	r.p += n
	return b
}
func (r *formReader) u(n int) uint64 {
	b := r.read(n)
	if b == nil {
		return 0
	}
	var v uint64
	for i := range b {
		v |= uint64(b[i]) << uint(i*8)
	}
	return v
}
func (r *formReader) align(base, n int) {
	if r.err == nil {
		pad := (n - (r.p-base)%n) % n
		r.read(pad)
	}
}
func (r *formReader) field(base, n int) uint64 { r.align(base, n); return r.u(n) }
func (r *formReader) text(flag uint32) string {
	b := r.read(int(flag & 0x7fffffff))
	r.read((4 - len(b)%4) % 4)
	if flag&0x80000000 != 0 {
		return decodeCodepage(1252, b)
	}
	if len(b)%2 != 0 {
		r.err = fmt.Errorf("odd UTF-16 forms string")
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}
func bit(m uint64, n uint) bool { return m&(1<<n) != 0 }
func (r *formReader) sized(version uint16) *formReader {
	if uint16(r.u(2)) != version {
		r.err = fmt.Errorf("unsupported forms version at %d", r.p-2)
	}
	n := int(r.u(2))
	b := r.read(n)
	return &formReader{b: b, err: r.err}
}

func parseFormSites(b []byte) ([]FormControl, error) {
	r := &formReader{b: b}
	block := r.sized(0x400)
	mask := block.u(4)
	for _, n := range []uint{1, 2, 3} {
		if bit(mask, n) {
			block.u(4)
		}
	}
	flags := uint64(0)
	if bit(mask, 6) {
		flags = block.u(4)
	}
	if block.err != nil {
		return nil, block.err
	}
	if bit(mask, 15) || bit(mask, 21) {
		return nil, fmt.Errorf("form pictures unsupported")
	}
	if bit(mask, 20) {
		guid := r.read(16)
		if len(guid) != 16 {
			return nil, r.err
		}
		switch binary.LittleEndian.Uint32(guid) {
		case 0x0be35203:
			if r.u(1) != 1 {
				return nil, fmt.Errorf("unsupported StdFont version")
			}
			r.read(9)
			n := int(r.u(1))
			r.read(n)
		case 0xafc20920:
			font := r.sized(0x200)
			if font.err != nil {
				return nil, font.err
			}
		default:
			return nil, fmt.Errorf("unsupported form font GUID")
		}
	}
	if flags&(1<<15) == 0 {
		count := int(r.u(2))
		if count > 4096 {
			return nil, fmt.Errorf("form class count exceeds limit")
		}
		for i := 0; i < count; i++ {
			c := r.sized(0)
			if c.err != nil {
				return nil, c.err
			}
		}
	}
	count := int(r.u(4))
	n := int(r.u(4))
	if count > 4096 {
		return nil, fmt.Errorf("form site count exceeds limit")
	}
	sites := &formReader{b: r.read(n), err: r.err}
	start := sites.p
	for left := count; left > 0 && sites.err == nil; {
		sites.u(1)
		t := sites.u(1)
		c := 1
		if t&128 != 0 {
			c = int(t & 127)
			if sites.u(1) != 1 || c == 0 {
				return nil, fmt.Errorf("invalid site type count")
			}
		} else if t != 1 {
			return nil, fmt.Errorf("unsupported site type")
		}
		left -= c
		if left < 0 {
			return nil, fmt.Errorf("site depth count mismatch")
		}
	}
	sites.align(start, 4)
	var out []FormControl
	for i := 0; i < count && sites.err == nil; i++ {
		offset := sites.p
		s := sites.sized(0)
		m := s.u(4)
		base := s.p
		vals := map[uint]uint64{}
		for _, f := range []struct {
			bit uint
			n   int
		}{{0, 4}, {1, 4}, {2, 4}, {3, 4}, {4, 4}, {5, 4}, {6, 2}, {7, 2}, {9, 2}, {11, 4}, {12, 4}, {13, 4}, {14, 4}} {
			if bit(m, f.bit) {
				vals[f.bit] = s.field(base, f.n)
			}
		}
		s.align(base, 4)
		name := s.text(uint32(vals[0]))
		tag := s.text(uint32(vals[1]))
		if bit(m, 8) {
			s.read(8)
		}
		tip := s.text(uint32(vals[11]))
		if s.err != nil {
			return out, s.err
		}
		props := map[string]string{"controltiptext": tip, "tag": tag}
		out = append(out, FormControl{Name: name, Offset: offset, SiteID: uint32(vals[2]), Class: uint16(vals[7]), ObjectSize: uint32(vals[5]), Properties: props})
	}
	return out, sites.err
}

func parseControlData(data []byte, class uint16) (map[string]string, error) {
	r := &formReader{b: data}
	s := r.sized(0x200)
	props := map[string]string{}
	switch class {
	case 21, 17:
		m := s.u(4)
		base := s.p
		caption := uint32(0)
		fields := []struct {
			bit uint
			n   int
		}{{0, 4}, {1, 4}, {2, 4}, {3, 4}, {4, 4}, {6, 1}, {7, 4}, {8, 2}, {9, 2}, {10, 2}, {11, 2}, {12, 2}}
		if class == 17 {
			fields = []struct {
				bit uint
				n   int
			}{{0, 4}, {1, 4}, {2, 4}, {3, 4}, {4, 4}, {6, 1}, {7, 2}, {8, 2}, {10, 2}}
		}
		for _, f := range fields {
			if bit(m, f.bit) {
				v := s.field(base, f.n)
				if f.bit == 3 {
					caption = uint32(v)
				}
			}
		}
		s.align(base, 4)
		props["caption"] = s.text(caption)
	case 15, 23, 24, 25, 26, 27, 28:
		m := s.u(8)
		base := s.p
		value, caption := uint32(0), uint32(0)
		for _, f := range []struct {
			bit uint
			n   int
		}{{0, 4}, {1, 4}, {2, 4}, {3, 4}, {4, 1}, {5, 1}, {6, 1}, {7, 1}, {9, 2}, {10, 4}, {11, 2}, {12, 2}, {13, 2}, {14, 2}, {15, 2}, {16, 1}, {17, 1}, {18, 1}, {20, 1}, {21, 1}, {22, 4}, {23, 4}, {24, 4}, {25, 4}, {26, 4}, {27, 2}, {28, 2}, {29, 2}, {32, 4}} {
			if bit(m, f.bit) {
				v := s.field(base, f.n)
				if f.bit == 22 {
					value = uint32(v)
				}
				if f.bit == 23 {
					caption = uint32(v)
				}
			}
		}
		s.align(base, 4)
		s.read(8)
		props["value"] = s.text(value)
		props["caption"] = s.text(caption)
	default:
		return nil, fmt.Errorf("unsupported forms control class %d", class)
	}
	return props, s.err
}

func extractForms(cfb *cfbReader, sourceFile string, res *Result) {
	for _, path := range cfb.listStreams() {
		if !strings.HasSuffix(path, "/f") {
			continue
		}
		root := strings.TrimSuffix(path, "/f")
		if cfb.find(root+"/o") == nil {
			continue
		}
		f, err := cfb.readStream(path)
		if err != nil {
			res.addDiag("warning", "forms", err.Error())
			continue
		}
		sites, err := parseFormSites(f)
		if err != nil {
			res.addDiag("warning", "forms", path+": "+err.Error())
		}
		o, err := cfb.readStream(root + "/o")
		if err != nil {
			res.addDiag("warning", "forms", err.Error())
			continue
		}
		offset := 0
		for _, site := range sites {
			site.Module = leafName(root)
			site.Stream = sourceFile + ":" + root + "/o"
			site.Offset = offset
			n := int(site.ObjectSize)
			if site.Class == 14 || site.Class == 7 || site.Class == 57 {
				child := fmt.Sprintf("%s/i%02d/f", root, site.SiteID)
				if b, err := cfb.readStream(child); err == nil {
					props, err := parseFormProperties(b)
					if err != nil {
						res.addDiag("warning", "forms", child+": "+err.Error())
					} else {
						for k, v := range props {
							site.Properties[k] = v
						}
						site.Stream = sourceFile + ":" + child
						site.Offset = 0
					}
				} else {
					res.addDiag("warning", "forms", err.Error())
				}
			}
			if n > len(o)-offset {
				res.addDiag("warning", "forms", "control object size exceeds stream: "+site.Name)
				break
			}
			if n > 0 {
				props, err := parseControlData(o[offset:offset+n], site.Class)
				if err != nil {
					res.addDiag("warning", "forms", site.Name+": "+err.Error())
				} else {
					for k, v := range props {
						site.Properties[k] = v
					}
				}
			}
			offset += n
			res.Forms = append(res.Forms, site)
		}
	}
}

func parseFormProperties(b []byte) (map[string]string, error) {
	r := &formReader{b: b}
	s := r.sized(0x400)
	m := s.u(4)
	base := s.p
	caption := uint32(0)
	for _, f := range []struct {
		bit uint
		n   int
	}{{1, 4}, {2, 4}, {3, 4}, {6, 4}, {7, 1}, {8, 1}, {9, 1}, {13, 4}, {15, 2}, {16, 1}, {17, 1}, {18, 4}, {19, 4}, {20, 2}, {21, 2}, {22, 4}, {23, 1}, {25, 1}, {26, 4}, {27, 4}} {
		if bit(m, f.bit) {
			v := s.field(base, f.n)
			if f.bit == 19 {
				caption = uint32(v)
			}
		}
	}
	s.align(base, 4)
	for _, n := range []uint{10, 11, 12} {
		if bit(m, n) {
			s.read(8)
		}
	}
	text := s.text(caption)
	return map[string]string{"caption": text}, s.err
}
