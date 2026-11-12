package extractor

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"

	"github.com/bodgit/sevenzip"
)

// Archive inputs (.zip, .7z) are how samples are exchanged: usually
// encrypted with "infected". Members are read in memory only, never written
// to disk, and analysed one by one.

// ArchivePasswords are tried on encrypted archives after the caller's.
var ArchivePasswords = []string{"infected", "malware", "virus"}

// Archive limits against decompression bombs.
const (
	maxArchiveMembers     = 512
	maxArchiveMemberSize  = 64 << 20
	maxArchiveTotalOutput = 512 << 20
)

// ArchiveMember is one file of an archive.
type ArchiveMember struct {
	Name string
	Data []byte
	// Password that decrypted the member ("" when it was not encrypted).
	Password  string
	Encrypted bool
	// Err tells why the member could not be read (Data is then nil).
	Err string
}

// Archive is the content of an archive input.
type Archive struct {
	Kind        string // zip | 7z
	Members     []ArchiveMember
	Diagnostics []Diagnostic
	LimitsHit   []string
}

var sevenZipMagic = []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}

// DetectContainer classifies inputs that are not Office documents but carry
// them: "zip" (a ZIP that is not an OOXML package), "7z", "eml", "msg"
// (Outlook) and "onenote". It returns "" for everything else.
func DetectContainer(data []byte) string {
	switch {
	case bytes.HasPrefix(data, sevenZipMagic):
		return "7z"
	case IsOneNote(data):
		return "onenote"
	case Detect(data) == FormatOOXML && !isOOXMLPackage(data):
		return "zip"
	case Detect(data) == FormatCFB && isOutlookMessage(data):
		return "msg"
	case looksLikeEmail(data) && Detect(data) != FormatMHT:
		return "eml"
	}
	return ""
}

// isOOXMLPackage reports a ZIP with an OOXML content-types part.
func isOOXMLPackage(data []byte) bool {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		// Unreadable directory: let the OOXML path report the error.
		return true
	}
	for i, f := range zr.File {
		if i > 4096 {
			break
		}
		name := strings.ToLower(strings.TrimPrefix(f.Name, "/"))
		if name == "[content_types].xml" || name == "_rels/.rels" || strings.HasPrefix(name, "word/") ||
			strings.HasPrefix(name, "xl/") || strings.HasPrefix(name, "ppt/") {
			return true
		}
	}
	return false
}

func archivePasswords(lim *Limits) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range append(append([]string(nil), lim.Passwords...), ArchivePasswords...) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// OpenArchive reads every member of a ZIP or 7z archive in memory.
func OpenArchive(data []byte, kind string, lim *Limits) (*Archive, error) {
	if lim == nil {
		l := DefaultLimits()
		lim = &l
	}
	switch kind {
	case "zip":
		return openZipArchive(data, lim)
	case "7z":
		return open7z(data, lim)
	}
	return nil, fmt.Errorf("unsupported archive %q", kind)
}

func (a *Archive) diag(sev, msg string) {
	a.Diagnostics = append(a.Diagnostics, Diagnostic{Severity: sev, Stage: "archive", Message: msg})
}

func (a *Archive) limit(name, msg string) {
	a.LimitsHit = append(a.LimitsHit, name)
	a.diag("warning", msg)
}

func openZipArchive(data []byte, lim *Limits) (*Archive, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, Wrap("zip", err)
	}
	a := &Archive{Kind: "zip"}
	pws := archivePasswords(lim)
	total := int64(0)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if len(a.Members) >= maxArchiveMembers {
			a.limit("MaxArchiveMembers", fmt.Sprintf("archive has more than %d members; the rest were not analysed", maxArchiveMembers))
			break
		}
		m := ArchiveMember{Name: f.Name, Encrypted: f.Flags&0x1 != 0 || f.Method == 99}
		switch {
		case f.UncompressedSize64 > maxArchiveMemberSize:
			m.Err = fmt.Sprintf("member is %d bytes, over the %d-byte limit", f.UncompressedSize64, maxArchiveMemberSize)
			a.limit("MaxArchiveMemberSize", f.Name+": "+m.Err)
		case f.CompressedSize64 > 0 && f.CompressedSize64*uint64(lim.MaxZipRatio) < f.UncompressedSize64:
			m.Err = "compression ratio above the limit (decompression bomb)"
			a.limit("MaxZipRatio", f.Name+": "+m.Err)
		case total+int64(f.UncompressedSize64) > maxArchiveTotalOutput:
			m.Err = "archive total size limit reached"
			a.limit("MaxArchiveTotal", f.Name+": "+m.Err)
		default:
			b, pw, err := openZipMember(f, pws, maxArchiveMemberSize)
			if err != nil {
				m.Err = err.Error()
				if errors.Is(err, errBadPassword) {
					m.Err = "encrypted; none of the candidate passwords worked"
				}
				a.diag("warning", f.Name+": "+m.Err)
			} else {
				m.Data, m.Password = b, pw
				total += int64(len(b))
			}
		}
		a.Members = append(a.Members, m)
	}
	return a, nil
}

func open7z(data []byte, lim *Limits) (*Archive, error) {
	a := &Archive{Kind: "7z"}
	r, err := new7zReader(data, "", false)
	usedPW := ""
	if err != nil {
		// The header itself may be encrypted.
		for _, pw := range archivePasswords(lim) {
			if r, err = new7zReader(data, pw, true); err == nil {
				usedPW = pw
				break
			}
		}
		if err != nil {
			return nil, Wrap("7z", err)
		}
	}
	pws := archivePasswords(lim)
	total := int64(0)
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if len(a.Members) >= maxArchiveMembers {
			a.limit("MaxArchiveMembers", fmt.Sprintf("archive has more than %d members; the rest were not analysed", maxArchiveMembers))
			break
		}
		m := ArchiveMember{Name: f.Name}
		size := int64(f.UncompressedSize)
		switch {
		case size > maxArchiveMemberSize:
			m.Err = fmt.Sprintf("member is %d bytes, over the %d-byte limit", size, maxArchiveMemberSize)
			a.limit("MaxArchiveMemberSize", f.Name+": "+m.Err)
		case total+size > maxArchiveTotalOutput:
			m.Err = "archive total size limit reached"
			a.limit("MaxArchiveTotal", f.Name+": "+m.Err)
		default:
			b, err := read7zMember(f, maxArchiveMemberSize)
			if err != nil && usedPW == "" {
				// Encrypted content with a plain header: reopen with each
				// password and read the member again.
				for _, pw := range pws {
					pr, perr := new7zReader(data, pw, true)
					if perr != nil {
						continue
					}
					for _, pf := range pr.File {
						if pf.Name == f.Name {
							if b, err = read7zMember(pf, maxArchiveMemberSize); err == nil {
								m.Password, m.Encrypted = pw, true
							}
							break
						}
					}
					if err == nil {
						break
					}
				}
			} else if usedPW != "" {
				m.Password, m.Encrypted = usedPW, true
			}
			if err != nil {
				m.Err = err.Error()
				a.diag("warning", f.Name+": "+m.Err)
			} else {
				m.Data = b
				total += int64(len(b))
			}
		}
		a.Members = append(a.Members, m)
	}
	return a, nil
}

// new7zReader opens a 7z archive, turning a panic of the decoder on a
// malformed header into an error.
func new7zReader(data []byte, pw string, withPassword bool) (r *sevenzip.Reader, err error) {
	if err := validate7z(data); err != nil {
		return nil, err
	}
	defer func() {
		if p := recover(); p != nil {
			r, err = nil, fmt.Errorf("malformed 7z archive: %v", p)
		}
	}()
	if withPassword {
		return sevenzip.NewReaderWithPassword(bytes.NewReader(data), int64(len(data)), pw)
	}
	return sevenzip.NewReader(bytes.NewReader(data), int64(len(data)))
}

func read7zMember(f *sevenzip.File, limit int64) (b []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			b, err = nil, fmt.Errorf("7z decoder failed: %v", p)
		}
	}()
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err = io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, ErrLimitExceeded
	}
	if f.CRC32 != 0 && crc32.ChecksumIEEE(b) != f.CRC32 {
		return nil, errBadPassword
	}
	return b, nil
}
