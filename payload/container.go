package payload

import (
	"bytes"
	"encoding/binary"
)

// File types that carry other files or install software.
const (
	MSIKind = "Windows Installer package (MSI)"
	ISOKind = "ISO 9660 disk image"
	CHMKind = "Compiled HTML Help (CHM)"
)

// clsidMSI is the root storage CLSID of Windows Installer packages
// ({000C1084-0000-0000-C000-000000000046}); patches (.msp, 000C1086) and
// transforms (.mst, 000C1082) differ only in the first byte.
var clsidMSI = []byte{0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

// isMSI reports an OLE compound file whose root storage is a Windows
// Installer database.
func isMSI(b []byte) bool {
	if len(b) < 0x200 {
		return false
	}
	shift := binary.LittleEndian.Uint16(b[0x1E:])
	if shift != 9 && shift != 12 {
		return false
	}
	size := 1 << shift
	dir := int(binary.LittleEndian.Uint32(b[0x30:]))
	off := (dir + 1) * size
	if dir < 0 || off+0x60 > len(b) || off < 0 {
		return false
	}
	clsid := b[off+0x50 : off+0x60]
	return bytes.Equal(clsid[1:], clsidMSI[1:]) && (clsid[0] == 0x84 || clsid[0] == 0x86 || clsid[0] == 0x82)
}

// IsISO reports an ISO 9660 image (the "CD001" volume descriptor at sector 16).
func IsISO(b []byte) bool {
	return len(b) >= 0x8006 && string(b[0x8001:0x8006]) == "CD001"
}
