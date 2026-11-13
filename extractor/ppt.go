package extractor

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
)

// PowerPoint 97-2003 ([MS-PPT]) keeps embedded OLE objects and the VBA
// project in ExOleObjStg records of the "PowerPoint Document" stream, as
// an OLE compound file that is zlib-compressed when the record instance
// is 1. Records are an 8-byte header (version/instance, type, length);
// version 0xF marks a container whose body is more records.
const (
	pptRecExOleObjStg = 0x1011
	pptMaxDepth       = 32
	pptMaxObjects     = 256
)

type pptStorage struct {
	offset int
	data   []byte
}

// pptStorages returns the OLE storages held by ExOleObjStg records.
func pptStorages(stream []byte, lim *Limits, res *Result) []pptStorage {
	var out []pptStorage
	var walk func(b []byte, base, depth int)
	walk = func(b []byte, base, depth int) {
		for p := 0; p+8 <= len(b) && len(out) < pptMaxObjects; {
			verInst := binary.LittleEndian.Uint16(b[p:])
			typ := binary.LittleEndian.Uint16(b[p+2:])
			n := int(binary.LittleEndian.Uint32(b[p+4:]))
			body := p + 8
			if n < 0 || body+n > len(b) {
				n = len(b) - body
			}
			rec := b[body : body+n]
			switch {
			case typ == pptRecExOleObjStg:
				data, err := pptStorageData(rec, verInst>>4 == 1, lim)
				if err != nil {
					res.addDiag("info", "ppt", fmt.Sprintf("ExOleObjStg at offset %d: %v", base+p, err))
				} else if bytes.HasPrefix(data, cfbMagic) {
					out = append(out, pptStorage{offset: base + p, data: data})
				}
			case verInst&0x0F == 0x0F && depth < pptMaxDepth:
				walk(rec, base+body, depth+1)
			}
			p = body + n
		}
	}
	walk(stream, 0, 0)
	return out
}

func pptStorageData(rec []byte, compressed bool, lim *Limits) ([]byte, error) {
	if !compressed {
		return rec, nil
	}
	if len(rec) < 4 {
		return nil, fmt.Errorf("truncated compressed storage")
	}
	size := int64(binary.LittleEndian.Uint32(rec))
	max := lim.MaxDecompressed
	if max <= 0 || max > 256<<20 {
		max = 256 << 20
	}
	if size > max {
		return nil, ErrLimitExceeded
	}
	zr, err := zlib.NewReader(bytes.NewReader(rec[4:]))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, max+1))
	if int64(len(out)) > max {
		return nil, ErrLimitExceeded
	}
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return out, nil
}

// scanPowerPoint extracts the VBA project and the OLE objects of a binary
// PowerPoint presentation.
func scanPowerPoint(ctx context.Context, cfb *cfbReader, lim *Limits, res *Result) {
	stream, err := cfb.readStream("PowerPoint Document")
	if err != nil {
		return
	}
	objects := 0
	for _, s := range pptStorages(stream, lim, res) {
		if ctx.Err() != nil {
			return
		}
		loc := "PowerPoint Document/ExOleObjStg@" + strconv.Itoa(s.offset)
		inner, err := parseCFB(s.data, lim)
		if err != nil {
			res.addDiag("info", "ppt", loc+": "+err.Error())
			continue
		}
		if inner.find("VBA/dir") != nil || inner.find("dir") != nil || len(inner.storageByLeafName("VBA")) > 0 {
			if err := extractFromCFB(ctx, s.data, loc, lim, res); err != nil {
				res.addDiag("info", "ppt", loc+": "+err.Error())
			}
			continue
		}
		scanOOXMLEmbedding(loc, s.data, lim, res)
		objects++
	}
	res.addCheck("PowerPoint ExOleObjStg storages (VBA project and " + strconv.Itoa(objects) + " OLE object(s))")
}
