package extractor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

// The 7z decoder used here (github.com/bodgit/sevenzip v1.6.1, the last
// release that builds with Go 1.23) sizes its slices from counts read from
// the archive header without checking them, so a crafted header of a few
// hundred bytes can make it allocate gigabytes. validate7z walks the header
// first ([7zFormat.txt]) and rejects any count larger than the bytes left to
// describe it. An LZMA-compressed header (the 7-Zip default) is decompressed
// with a size cap and checked too; a header that is also encrypted (-mhe)
// can only be checked up to its outer description.

const max7zHeader = 16 << 20

var errBad7z = errors.New("malformed 7z header")

type szReader struct {
	b []byte
	p int
}

func (r *szReader) left() uint64 { return uint64(len(r.b) - r.p) }

func (r *szReader) byte() (byte, error) {
	if r.p >= len(r.b) {
		return 0, errBad7z
	}
	c := r.b[r.p]
	r.p++
	return c, nil
}

func (r *szReader) skip(n uint64) error {
	if n > r.left() {
		return errBad7z
	}
	r.p += int(n)
	return nil
}

// number reads a 7z variable-length integer.
func (r *szReader) number() (uint64, error) {
	first, err := r.byte()
	if err != nil {
		return 0, err
	}
	var v uint64
	mask := byte(0x80)
	for i := 0; i < 8; i++ {
		if first&mask == 0 {
			hi := uint64(first) & (uint64(mask) - 1)
			return v | hi<<(8*i), nil
		}
		c, err := r.byte()
		if err != nil {
			return 0, err
		}
		v |= uint64(c) << (8 * i)
		mask >>= 1
	}
	return v, nil
}

// count reads a number that sizes an array whose elements take at least
// minBytes each (minBytes 0 means bits).
func (r *szReader) count(minBytes uint64) (uint64, error) {
	n, err := r.number()
	if err != nil {
		return 0, err
	}
	limit := r.left()
	if minBytes == 0 {
		limit *= 8
	} else {
		limit /= minBytes
	}
	if n > limit {
		return 0, fmt.Errorf("%w: count %d exceeds the remaining %d bytes", errBad7z, n, r.left())
	}
	return n, nil
}

func (r *szReader) bits(n uint64) ([]bool, error) {
	all, err := r.byte()
	if err != nil {
		return nil, err
	}
	out := make([]bool, n)
	if all != 0 {
		for i := range out {
			out[i] = true
		}
		return out, nil
	}
	if (n+7)/8 > r.left() {
		return nil, errBad7z
	}
	for i := uint64(0); i < n; i++ {
		out[i] = r.b[r.p+int(i/8)]&(0x80>>(i%8)) != 0
	}
	r.p += int((n + 7) / 8)
	return out, nil
}

func (r *szReader) digests(n uint64) error {
	def, err := r.bits(n)
	if err != nil {
		return err
	}
	for _, d := range def {
		if d {
			if err := r.skip(4); err != nil {
				return err
			}
		}
	}
	return nil
}

type szFolder struct {
	outs   uint64
	coder  []byte // id of the first coder
	props  []byte
	unpack []uint64
}

type szStreams struct {
	packPos   uint64
	packSizes []uint64
	folders   []szFolder
}

func (r *szReader) folder() (szFolder, error) {
	var f szFolder
	coders, err := r.count(1)
	if err != nil {
		return f, err
	}
	if coders == 0 || coders > 64 {
		return f, errBad7z
	}
	var ins uint64
	for i := uint64(0); i < coders; i++ {
		flag, err := r.byte()
		if err != nil {
			return f, err
		}
		idSize := uint64(flag & 0x0F)
		id := r.b[r.p:min(len(r.b), r.p+int(idSize))]
		if err := r.skip(idSize); err != nil {
			return f, err
		}
		in, out := uint64(1), uint64(1)
		if flag&0x10 != 0 {
			if in, err = r.count(1); err != nil {
				return f, err
			}
			if out, err = r.count(1); err != nil {
				return f, err
			}
		}
		var props []byte
		if flag&0x20 != 0 {
			n, err := r.count(1)
			if err != nil {
				return f, err
			}
			props = r.b[r.p : r.p+int(n)]
			r.p += int(n)
		}
		if i == 0 {
			f.coder, f.props = id, props
		}
		ins += in
		f.outs += out
	}
	if f.outs == 0 || f.outs > 64 || ins > 64 {
		return f, errBad7z
	}
	bindPairs := f.outs - 1
	for i := uint64(0); i < 2*bindPairs; i++ {
		if _, err := r.number(); err != nil {
			return f, err
		}
	}
	if ins < bindPairs {
		return f, errBad7z
	}
	if packed := ins - bindPairs; packed > 1 {
		for i := uint64(0); i < packed; i++ {
			if _, err := r.number(); err != nil {
				return f, err
			}
		}
	}
	return f, nil
}

// streamsInfo validates a StreamsInfo block and returns what is needed to
// decode an encoded header.
func (r *szReader) streamsInfo(totalFiles *uint64) (*szStreams, error) {
	s := &szStreams{}
	for {
		id, err := r.number()
		if err != nil {
			return nil, err
		}
		switch id {
		case 0x00: // kEnd
			return s, nil
		case 0x06: // kPackInfo
			if s.packPos, err = r.number(); err != nil {
				return nil, err
			}
			n, err := r.count(1)
			if err != nil {
				return nil, err
			}
			for {
				pid, err := r.number()
				if err != nil {
					return nil, err
				}
				if pid == 0 {
					break
				}
				switch pid {
				case 0x09:
					for i := uint64(0); i < n; i++ {
						v, err := r.number()
						if err != nil {
							return nil, err
						}
						s.packSizes = append(s.packSizes, v)
					}
				case 0x0A:
					if err := r.digests(n); err != nil {
						return nil, err
					}
				default:
					return nil, errBad7z
				}
			}
		case 0x07: // kUnPackInfo
			if k, err := r.number(); err != nil || k != 0x0B {
				return nil, errBad7z
			}
			n, err := r.count(2)
			if err != nil {
				return nil, err
			}
			if ext, err := r.byte(); err != nil || ext != 0 {
				return nil, errBad7z
			}
			for i := uint64(0); i < n; i++ {
				f, err := r.folder()
				if err != nil {
					return nil, err
				}
				s.folders = append(s.folders, f)
			}
			if k, err := r.number(); err != nil || k != 0x0C {
				return nil, errBad7z
			}
			for i := range s.folders {
				for j := uint64(0); j < s.folders[i].outs; j++ {
					v, err := r.number()
					if err != nil {
						return nil, err
					}
					s.folders[i].unpack = append(s.folders[i].unpack, v)
				}
			}
			for {
				pid, err := r.number()
				if err != nil {
					return nil, err
				}
				if pid == 0 {
					break
				}
				if pid != 0x0A {
					return nil, errBad7z
				}
				if err := r.digests(uint64(len(s.folders))); err != nil {
					return nil, err
				}
			}
		case 0x08: // kSubStreamsInfo
			streams := uint64(len(s.folders))
			pid, err := r.number()
			if err != nil {
				return nil, err
			}
			if pid == 0x0D {
				streams = 0
				for range s.folders {
					n, err := r.count(0)
					if err != nil {
						return nil, err
					}
					streams += n
					if streams > uint64(len(r.b)) {
						return nil, errBad7z
					}
				}
				if pid, err = r.number(); err != nil {
					return nil, err
				}
			}
			*totalFiles += streams
			for pid != 0 {
				switch pid {
				case 0x09:
					for i := uint64(0); i+uint64(len(s.folders)) < streams; i++ {
						if _, err := r.number(); err != nil {
							return nil, err
						}
					}
				case 0x0A:
					if err := r.digests(streams); err != nil {
						return nil, err
					}
				default:
					return nil, errBad7z
				}
				if pid, err = r.number(); err != nil {
					return nil, err
				}
			}
		default:
			return nil, errBad7z
		}
	}
}

func (r *szReader) filesInfo() error {
	if _, err := r.count(2); err != nil {
		return err
	}
	for {
		typ, err := r.number()
		if err != nil {
			return err
		}
		if typ == 0 {
			return nil
		}
		size, err := r.number()
		if err != nil {
			return err
		}
		if err := r.skip(size); err != nil {
			return err
		}
	}
}

// header validates a plain header (after the kHeader byte).
func (r *szReader) header() error {
	var files uint64
	for {
		id, err := r.number()
		if err != nil {
			return err
		}
		switch id {
		case 0x00:
			return nil
		case 0x02: // kArchiveProperties
			for {
				t, err := r.number()
				if err != nil {
					return err
				}
				if t == 0 {
					break
				}
				n, err := r.number()
				if err != nil {
					return err
				}
				if err := r.skip(n); err != nil {
					return err
				}
			}
		case 0x03, 0x04: // kAdditionalStreamsInfo, kMainStreamsInfo
			if _, err := r.streamsInfo(&files); err != nil {
				return err
			}
		case 0x05:
			if err := r.filesInfo(); err != nil {
				return err
			}
		default:
			return errBad7z
		}
	}
}

// validate7z checks the archive header before the decoder sees it.
func validate7z(data []byte) error {
	if len(data) < 32 {
		return ErrTruncated
	}
	off, size := binary.LittleEndian.Uint64(data[12:]), binary.LittleEndian.Uint64(data[20:])
	if off > uint64(len(data)) || size > uint64(len(data)) || 32+off+size > uint64(len(data)) {
		return fmt.Errorf("%w: next header outside the file", errBad7z)
	}
	if size == 0 {
		return nil
	}
	return validate7zHeader(data, data[32+off:32+off+size], 0)
}

func validate7zHeader(data, hdr []byte, depth int) error {
	r := &szReader{b: hdr}
	id, err := r.number()
	if err != nil {
		return err
	}
	switch id {
	case 0x01:
		return r.header()
	case 0x17: // kEncodedHeader
		if depth > 2 {
			return errBad7z
		}
		var files uint64
		s, err := r.streamsInfo(&files)
		if err != nil {
			return err
		}
		if len(s.folders) != 1 || len(s.packSizes) == 0 || len(s.folders[0].unpack) == 0 {
			return errBad7z
		}
		f := s.folders[0]
		unpack := f.unpack[len(f.unpack)-1]
		if unpack > max7zHeader {
			return fmt.Errorf("%w: header of %d bytes", errBad7z, unpack)
		}
		start := 32 + s.packPos
		if start > uint64(len(data)) || s.packSizes[0] > uint64(len(data))-start {
			return errBad7z
		}
		// Only a plain LZMA header can be checked further; an encrypted one
		// is left to the decoder (which then needs the password).
		if !bytes.Equal(f.coder, []byte{0x03, 0x01, 0x01}) || len(f.props) != 5 {
			return nil
		}
		stream := append(append(append([]byte(nil), f.props...), binary.LittleEndian.AppendUint64(nil, unpack)...), data[start:start+s.packSizes[0]]...)
		lr, err := lzma.NewReader(bytes.NewReader(stream))
		if err != nil {
			return fmt.Errorf("%w: %v", errBad7z, err)
		}
		plain, err := io.ReadAll(io.LimitReader(lr, int64(unpack)))
		if err != nil && len(plain) == 0 {
			return fmt.Errorf("%w: %v", errBad7z, err)
		}
		return validate7zHeader(data, plain, depth+1)
	}
	return errBad7z
}
