package extractor

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"golang.org/x/text/encoding/charmap"
)

// Document text is what macros read through ActiveDocument.Content,
// .Paragraphs(n).Range.Text, etc. Droppers frequently store their payload in
// the body (often in white or tiny font) and read it back at run time, so the
// emulator needs it. Paragraphs end with "\r" exactly as Word reports them.

// maxDocText caps the extracted body text (in characters).
const maxDocText = 16 << 20

// wordBinaryText extracts the main-document text of a Word 97-2003 file
// ([MS-DOC] FIB → Clx → piece table). Only the main story (ccpText) is kept.
func wordBinaryText(cfb *cfbReader) (string, error) { return wordStoryText(cfb, false) }

// wordStoryText extracts the main story, or with allStories every story
// (footnotes, headers, comments, endnotes, text boxes) that follows it in
// the CP space; fields can sit in any of them.
func wordStoryText(cfb *cfbReader, allStories bool) (string, error) {
	wd, err := cfb.readStream("WordDocument")
	if err != nil {
		return "", err
	}
	if len(wd) < 0x1AA || binary.LittleEndian.Uint16(wd) != 0xA5EC {
		return "", fmt.Errorf("WordDocument: invalid FIB")
	}
	flags := binary.LittleEndian.Uint16(wd[0x0A:])
	if flags&0x0100 != 0 { // fEncrypted
		return "", fmt.Errorf("WordDocument: encrypted or obfuscated")
	}
	table := "0Table"
	if flags&0x0200 != 0 { // fWhichTblStm
		table = "1Table"
	}
	tbl, err := cfb.readStream(table)
	if err != nil {
		return "", err
	}
	ccpText := int64(binary.LittleEndian.Uint32(wd[0x4C:]))
	if allStories {
		// ccpFtn, ccpHdd, ccpMcr, ccpAtn, ccpEdn, ccpTxbx, ccpHdrTxbx
		for off := 0x50; off <= 0x68; off += 4 {
			if n := int64(binary.LittleEndian.Uint32(wd[off:])); n > 0 && n < maxDocText {
				ccpText += n
			}
		}
	}
	fcClx := int64(binary.LittleEndian.Uint32(wd[0x1A2:]))
	lcbClx := int64(binary.LittleEndian.Uint32(wd[0x1A6:]))
	if fcClx < 0 || lcbClx <= 0 || fcClx+lcbClx > int64(len(tbl)) {
		return "", fmt.Errorf("Clx out of range")
	}
	clx := tbl[fcClx : fcClx+lcbClx]
	// Skip Prc entries (grpprl blocks) that precede the Pcdt.
	for len(clx) > 0 && clx[0] == 0x01 {
		if len(clx) < 3 {
			return "", fmt.Errorf("truncated Prc")
		}
		n := int(binary.LittleEndian.Uint16(clx[1:]))
		if 3+n > len(clx) {
			return "", fmt.Errorf("truncated Prc")
		}
		clx = clx[3+n:]
	}
	if len(clx) < 5 || clx[0] != 0x02 {
		return "", fmt.Errorf("Pcdt not found")
	}
	lcb := int(binary.LittleEndian.Uint32(clx[1:]))
	plc := clx[5:]
	if lcb > len(plc) || lcb < 4 || (lcb-4)%12 != 0 {
		return "", fmt.Errorf("invalid PlcPcd")
	}
	n := (lcb - 4) / 12
	cps := make([]int64, n+1)
	for i := range cps {
		cps[i] = int64(binary.LittleEndian.Uint32(plc[i*4:]))
	}
	pcds := plc[(n+1)*4:]
	win1252 := charmap.Windows1252.NewDecoder()
	var out strings.Builder
	total := int64(0)
	for i := 0; i < n && total < ccpText && total < maxDocText; i++ {
		count := cps[i+1] - cps[i]
		if count <= 0 {
			continue
		}
		if total+count > ccpText {
			count = ccpText - total
		}
		fc := int64(binary.LittleEndian.Uint32(pcds[i*8+2:]))
		if fc&0x40000000 != 0 { // fCompressed: 8-bit text at fc/2
			off := (fc &^ 0x40000000) / 2
			if off < 0 || off+count > int64(len(wd)) {
				return out.String(), fmt.Errorf("piece %d out of range", i)
			}
			s, _ := win1252.Bytes(wd[off : off+count])
			out.Write(s)
		} else {
			if fc < 0 || fc+2*count > int64(len(wd)) {
				return out.String(), fmt.Errorf("piece %d out of range", i)
			}
			u := make([]uint16, count)
			for j := range u {
				u[j] = binary.LittleEndian.Uint16(wd[fc+int64(j)*2:])
			}
			out.WriteString(string(utf16.Decode(u)))
		}
		total += count
	}
	return out.String(), nil
}

// ooxmlDocumentText extracts word/document.xml body text from a .docx/.docm.
func ooxmlDocumentText(data []byte, lim *Limits) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	for _, f := range zr.File {
		if !strings.EqualFold(f.Name, "word/document.xml") {
			continue
		}
		if f.UncompressedSize64 > uint64(lim.MaxModuleSize) ||
			(f.CompressedSize64 > 0 && f.CompressedSize64*uint64(lim.MaxZipRatio) < f.UncompressedSize64) {
			return "", fmt.Errorf("document.xml exceeds limits")
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		defer rc.Close()
		return wordXMLText(io.LimitReader(rc, lim.MaxModuleSize))
	}
	return "", nil
}

func wordXMLText(r io.Reader) (string, error) {
	dec := xml.NewDecoder(r)
	var out strings.Builder
	inText := false
	for out.Len() < maxDocText {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out.String(), err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "t":
				inText = true
			case "tab":
				out.WriteByte('\t')
			case "br", "cr":
				out.WriteByte('\v')
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "t":
				inText = false
			case "p":
				out.WriteByte('\r')
			}
		case xml.CharData:
			if inText {
				out.Write(t)
			}
		}
	}
	return out.String(), nil
}
