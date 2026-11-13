package extractor

import "time"

// StorageTime is the creation and modification time of a CFB storage (the
// root entry, the VBA project storages, OLE object storages...), as
// recorded by the application that wrote the file. They date the
// document's construction: for instance when the macros were last saved.
type StorageTime struct {
	Path     string    `json:"path"`
	Created  time.Time `json:"created,omitempty"`
	Modified time.Time `json:"modified,omitempty"`
}

const maxStorageTimes = 256

// filetime converts a Windows FILETIME; implausible values (before 1980 or
// after 2100, which only corrupt or forged files hold) give the zero time.
func filetime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000 // 1601-01-01 to 1970-01-01 in 100 ns
	if ft < epochDiff {
		return time.Time{}
	}
	t := time.Unix(0, 0).Add(time.Duration(ft-epochDiff) * 100).UTC()
	if t.Year() < 1980 || t.Year() > 2100 {
		return time.Time{}
	}
	return t
}

// storageTimes lists the storages that carry a timestamp.
func storageTimes(cfb *cfbReader) []StorageTime {
	var out []StorageTime
	for i, e := range cfb.entries {
		if e.objType != 1 && e.objType != 5 {
			continue
		}
		c, m := filetime(e.created), filetime(e.modified)
		if c.IsZero() && m.IsZero() {
			continue
		}
		path := e.path
		if i == 0 {
			path = "Root Entry"
		}
		out = append(out, StorageTime{Path: path, Created: c, Modified: m})
		if len(out) >= maxStorageTimes {
			break
		}
	}
	return out
}
