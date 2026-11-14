package extractor

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/debugactiveprocess/MaldocTrace/internal/cfbtest"
)

var clsidMSI = [16]byte{0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

func TestCFBVersion4(t *testing.T) {
	data := bytes.Repeat([]byte("MSI!"), 2000) // 8000 bytes: two 4096-byte sectors
	file := cfbtest.BuildV4("Payload", data, clsidMSI)
	lim := DefaultLimits()
	r, err := parseCFB(file, &lim)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.readStream("Payload")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("stream %d bytes, err %v", len(got), err)
	}
}

// isoRecord encodes an ISO 9660 directory record.
func isoRecord(name string, extent, size uint32, dir bool) []byte {
	l := 33 + len(name)
	if l%2 == 1 {
		l++
	}
	rec := make([]byte, l)
	rec[0] = byte(l)
	binary.LittleEndian.PutUint32(rec[2:], extent)
	binary.BigEndian.PutUint32(rec[6:], extent)
	binary.LittleEndian.PutUint32(rec[10:], size)
	binary.BigEndian.PutUint32(rec[14:], size)
	if dir {
		rec[25] = 2
	}
	rec[32] = byte(len(name))
	copy(rec[33:], name)
	return rec
}

// buildISO lays out an image with README.LNK at the root and
// SUB/PAYLOAD.DLL in a subdirectory.
func buildISO(lnk, dll []byte) []byte {
	const s = isoSector
	img := make([]byte, 24*s)
	pvd := img[16*s:]
	pvd[0] = 1
	copy(pvd[1:], "CD001")
	pvd[6] = 1
	copy(pvd[156:], isoRecord("\x00", 18, s, true))
	term := img[17*s:]
	term[0] = 255
	copy(term[1:], "CD001")
	root := isoRecord("\x00", 18, s, true)
	root = append(root, isoRecord("\x01", 18, s, true)...)
	root = append(root, isoRecord("README.LNK;1", 20, uint32(len(lnk)), false)...)
	root = append(root, isoRecord("SUB", 19, s, true)...)
	root = append(root, isoRecord("LOOP", 18, s, true)...) // cycle back to the root
	copy(img[18*s:], root)
	sub := isoRecord("\x00", 19, s, true)
	sub = append(sub, isoRecord("PAYLOAD.DLL;1", 21, uint32(len(dll)), false)...)
	copy(img[19*s:], sub)
	copy(img[20*s:], lnk)
	copy(img[21*s:], dll)
	return img
}

func TestISOMembers(t *testing.T) {
	lnk := append([]byte{0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0}, make([]byte, 60)...)
	dll := append([]byte("MZ"), make([]byte, 300)...)
	img := buildISO(lnk, dll)
	lim := DefaultLimits()
	if DetectContainer(img) != "iso" {
		t.Fatalf("detected %q", DetectContainer(img))
	}
	a, err := OpenArchive(img, "iso", &lim)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]byte{}
	for _, m := range a.Members {
		got[m.Name] = m.Data
	}
	if len(got) != 2 || !bytes.Equal(got["README.LNK"], lnk) || !bytes.Equal(got["SUB/PAYLOAD.DLL"], dll) {
		t.Fatalf("members %+v", a.Members)
	}
}

func FuzzISO(f *testing.F) {
	f.Add(buildISO([]byte("x"), []byte("MZ")))
	f.Fuzz(func(t *testing.T, b []byte) {
		if IsISO(b) {
			lim := DefaultLimits()
			_, _ = openISO(b, &lim)
		}
	})
}
