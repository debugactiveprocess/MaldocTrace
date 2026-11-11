package extractor

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// CFB (MS-CFB) special FAT/DIFAT constants.
const (
	fatFreeSect   = 0xFFFFFFFF
	fatEndOfChain = 0xFFFFFFFE
	fatFatSect    = 0xFFFFFFFD
	fatDifSect    = 0xFFFFFFFC
)

const maxRegularSector = 0xFFFFFFFA

// cfbEntry is a single directory entry in the CFB directory tree.
type cfbEntry struct {
	name        string
	objType     byte
	left        int32
	right       int32
	child       int32
	startSector uint32
	size        uint64
	path        string
}

// cfbReader is a parsed CFB (OLE2 compound file) container.
type cfbReader struct {
	data         []byte
	sectorShift  uint32
	sectorSize   uint32
	miniShift    uint32
	miniSector   uint32
	miniCutoff   uint64
	fat          []uint32 // full FAT (flat)
	miniFat      []uint32
	entries      []*cfbEntry
	miniStream   []byte
	firstDirSect uint32
}

// parseCFB parses a CFB container from data. Limits bound entry and sector
// counts to protect against cyclic or adversarial structures.
func parseCFB(data []byte, lim *Limits) (*cfbReader, error) {
	if len(data) < 512 {
		return nil, Wrap("cfb", ErrTruncated)
	}
	if !equalBytes(data[:8], cfbMagic) {
		return nil, Wrap("cfb", fmt.Errorf("bad CFB magic"))
	}
	byteOrder := binary.LittleEndian.Uint16(data[0x1C:])
	if byteOrder != 0xFFFE {
		return nil, Wrap("cfb", fmt.Errorf("bad byte order marker 0x%04X", byteOrder))
	}
	r := &cfbReader{data: data}
	r.sectorShift = uint32(binary.LittleEndian.Uint16(data[0x1E:]))
	if r.sectorShift != 9 && r.sectorShift != 12 {
		return nil, Wrap("cfb", fmt.Errorf("unsupported sector shift %d", r.sectorShift))
	}
	r.sectorSize = 1 << r.sectorShift
	r.miniShift = uint32(binary.LittleEndian.Uint16(data[0x20:]))
	if r.miniShift == 0 || r.miniShift > 12 {
		r.miniShift = 6
	}
	r.miniSector = 1 << r.miniShift

	numFatSectors := binary.LittleEndian.Uint32(data[0x2C:])
	r.firstDirSect = binary.LittleEndian.Uint32(data[0x30:])
	r.miniCutoff = uint64(binary.LittleEndian.Uint32(data[0x38:]))
	if r.miniCutoff == 0 {
		r.miniCutoff = 4096
	}
	firstMiniFat := binary.LittleEndian.Uint32(data[0x3C:])
	numMiniFat := binary.LittleEndian.Uint32(data[0x40:])
	firstDifat := binary.LittleEndian.Uint32(data[0x44:])
	numDifat := binary.LittleEndian.Uint32(data[0x48:])

	// Build the DIFAT array (list of FAT-sector numbers).
	difat := make([]uint32, 0, 128)
	for i := 0; i < 109; i++ {
		v := binary.LittleEndian.Uint32(data[0x4C+i*4:])
		if v == fatFreeSect {
			continue
		}
		difat = append(difat, v)
	}
	// Extension DIFAT sectors.
	seenDifat := make(map[uint32]bool)
	cur := firstDifat
	for i := 0; cur <= maxRegularSector && i < int(numDifat)+int(lim.MaxContainerEntries); i++ {
		if seenDifat[cur] {
			return nil, Wrap("cfb", fmt.Errorf("cyclic DIFAT chain at sector %d", cur))
		}
		seenDifat[cur] = true
		sect, err := r.readSectorBytes(cur)
		if err != nil {
			return nil, Wrap("cfb", err)
		}
		per := int(r.sectorSize/4) - 1
		for j := 0; j < per; j++ {
			v := binary.LittleEndian.Uint32(sect[j*4:])
			if v == fatFreeSect {
				continue
			}
			difat = append(difat, v)
		}
		cur = binary.LittleEndian.Uint32(sect[per*4:])
	}

	// Read all FAT sectors into one flat FAT.
	if numFatSectors == 0 {
		numFatSectors = uint32(len(difat))
	}
	fat := make([]uint32, 0, int(numFatSectors)*int(r.sectorSize/4))
	maxFatEntries := int(lim.MaxContainerEntries) * 128
	for i := 0; i < len(difat) && i < int(numFatSectors); i++ {
		sect := difat[i]
		if sect > maxRegularSector {
			break
		}
		b, err := r.readSectorBytes(sect)
		if err != nil {
			return nil, Wrap("cfb", err)
		}
		for j := 0; j+4 <= len(b); j += 4 {
			fat = append(fat, binary.LittleEndian.Uint32(b[j:]))
			if len(fat) > maxFatEntries {
				return nil, Wrap("cfb", ErrLimitExceeded)
			}
		}
	}
	r.fat = fat

	if err := r.readDirectory(lim); err != nil {
		return nil, err
	}
	// Read mini FAT.
	if numMiniFat > 0 && firstMiniFat <= maxRegularSector {
		miniFat := make([]uint32, 0, int(numMiniFat)*int(r.sectorSize/4))
		cur = firstMiniFat
		for i := 0; cur <= maxRegularSector && i < int(numMiniFat); i++ {
			b, err := r.readSectorBytes(cur)
			if err != nil {
				return nil, Wrap("cfb", err)
			}
			for j := 0; j+4 <= len(b); j += 4 {
				miniFat = append(miniFat, binary.LittleEndian.Uint32(b[j:]))
			}
			cur = r.nextSector(cur)
		}
		r.miniFat = miniFat
	}
	// The root entry's stream is the mini stream.
	if len(r.entries) > 0 {
		root := r.entries[0]
		ms, err := r.readChain(root.startSector, root.size)
		if err != nil {
			return nil, Wrap("cfb.ministream", err)
		}
		r.miniStream = ms
	}
	r.buildTree()
	return r, nil
}

// equalBytes compares two byte slices.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// readSectorBytes returns the raw bytes of a regular sector.
func (r *cfbReader) readSectorBytes(sector uint32) ([]byte, error) {
	off := int64(512) + int64(sector)*int64(r.sectorSize)
	if off < 0 || off+int64(r.sectorSize) > int64(len(r.data)) {
		return nil, ErrTruncated
	}
	return r.data[off : off+int64(r.sectorSize)], nil
}

// nextSector returns the following sector in the FAT chain, or fatEndOfChain.
func (r *cfbReader) nextSector(sector uint32) uint32 {
	if int64(sector) >= int64(len(r.fat)) {
		return fatEndOfChain
	}
	return r.fat[sector]
}

func (r *cfbReader) readDirectory(lim *Limits) error {
	sector := r.firstDirSect
	seen := make(map[uint32]bool)
	per := int(r.sectorSize / 128)
	for sector <= maxRegularSector {
		if seen[sector] {
			return Wrap("cfb", fmt.Errorf("cyclic directory chain at sector %d", sector))
		}
		seen[sector] = true
		b, err := r.readSectorBytes(sector)
		if err != nil {
			return Wrap("cfb", err)
		}
		for i := 0; i < per; i++ {
			eb := b[i*128 : i*128+128]
			nameLen := binary.LittleEndian.Uint16(eb[64:])
			if nameLen < 2 || nameLen > 64 {
				nameLen = 0
			}
			name := strings.TrimRight(decodeUTF16(eb[0:nameLen], binary.LittleEndian), "\x00")
			objType := eb[66]
			if objType == 0 {
				return nil // empty entry terminates the directory
			}
			left := int32(binary.LittleEndian.Uint32(eb[68:]))
			right := int32(binary.LittleEndian.Uint32(eb[72:]))
			child := int32(binary.LittleEndian.Uint32(eb[76:]))
			start := binary.LittleEndian.Uint32(eb[116:])
			size := binary.LittleEndian.Uint64(eb[120:])
			r.entries = append(r.entries, &cfbEntry{
				name:        name,
				objType:     objType,
				left:        left,
				right:       right,
				child:       child,
				startSector: start,
				size:        size,
			})
			if len(r.entries) > int(lim.MaxContainerEntries) {
				return Wrap("cfb", ErrLimitExceeded)
			}
		}
		sector = r.nextSector(sector)
	}
	return nil
}

// buildTree assigns each entry a slash-separated path by walking the
// red-black child/sibling tree from the root storage.
func (r *cfbReader) buildTree() {
	if len(r.entries) == 0 {
		return
	}
	r.entries[0].path = ""
	visited := make([]bool, len(r.entries))
	var inOrder func(node int32, parent string)
	inOrder = func(node int32, parent string) {
		if node < 0 || int(node) >= len(r.entries) || visited[node] {
			return
		}
		visited[node] = true
		e := r.entries[node]
		inOrder(e.left, parent)
		if parent == "" {
			e.path = e.name
		} else {
			e.path = parent + "/" + e.name
		}
		inOrder(e.right, parent)
		inOrder(e.child, e.path)
	}
	inOrder(r.entries[0].child, "")
}

// find returns the entry with the exact path, or nil.
func (r *cfbReader) find(path string) *cfbEntry {
	for _, e := range r.entries {
		if e.path == path {
			return e
		}
	}
	return nil
}

// storageByLeafName returns storage entries whose leaf component equals name.
func (r *cfbReader) storageByLeafName(name string) []*cfbEntry {
	var out []*cfbEntry
	for _, e := range r.entries {
		if e.objType == 1 && leafName(e.path) == name {
			out = append(out, e)
		}
	}
	return out
}

func leafName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

// readChain reads stream data stored in regular sectors, following the FAT.
func (r *cfbReader) readChain(start uint32, size uint64) ([]byte, error) {
	if size > uint64(len(r.data)) {
		return nil, fmt.Errorf("stream size exceeds container bounds")
	}
	if size == 0 {
		return nil, nil
	}
	out := make([]byte, 0, size)
	sector := start
	seen := make(map[uint32]bool)
	for len(out) < int(size) && sector <= maxRegularSector {
		if seen[sector] {
			return nil, fmt.Errorf("cyclic FAT chain at sector %d", sector)
		}
		seen[sector] = true
		b, err := r.readSectorBytes(sector)
		if err != nil {
			return nil, err
		}
		remaining := int(size) - len(out)
		if remaining < len(b) {
			b = b[:remaining]
		}
		out = append(out, b...)
		sector = r.nextSector(sector)
	}
	if len(out) < int(size) {
		return nil, ErrTruncated
	}
	return out, nil
}

// readMiniChain reads stream data stored in mini sectors within the mini stream.
func (r *cfbReader) readMiniChain(start uint32, size uint64) ([]byte, error) {
	if size > uint64(len(r.miniStream)) {
		return nil, fmt.Errorf("mini stream size exceeds container bounds")
	}
	if size == 0 {
		return nil, nil
	}
	out := make([]byte, 0, size)
	sector := start
	seen := map[uint32]bool{}
	for len(out) < int(size) && sector <= maxRegularSector {
		if seen[sector] {
			return nil, fmt.Errorf("cyclic mini FAT chain")
		}
		seen[sector] = true
		if int64(sector) >= int64(len(r.miniFat)) {
			return nil, ErrTruncated
		}
		off := int64(sector) * int64(r.miniSector)
		if off+int64(r.miniSector) > int64(len(r.miniStream)) {
			return nil, ErrTruncated
		}
		b := r.miniStream[off : off+int64(r.miniSector)]
		remaining := int(size) - len(out)
		if remaining < len(b) {
			b = b[:remaining]
		}
		out = append(out, b...)
		next := r.miniFat[sector]
		if next == sector || next == fatFreeSect {
			return nil, fmt.Errorf("cyclic mini FAT chain at sector %d", sector)
		}
		sector = next
	}
	if len(out) < int(size) {
		return nil, ErrTruncated
	}
	return out, nil
}

// readStream reads a logical stream by its full path.
func (r *cfbReader) readStream(path string) ([]byte, error) {
	e := r.find(path)
	if e == nil {
		return nil, fmt.Errorf("cfb: stream %q not found", path)
	}
	if e.objType != 2 {
		return nil, fmt.Errorf("cfb: %q is not a stream", path)
	}
	if e.size < r.miniCutoff {
		return r.readMiniChain(e.startSector, e.size)
	}
	return r.readChain(e.startSector, e.size)
}

// listStreams returns the paths of all stream entries.
func (r *cfbReader) listStreams() []string {
	var out []string
	for _, e := range r.entries {
		if e.objType == 2 {
			out = append(out, e.path)
		}
	}
	return out
}
