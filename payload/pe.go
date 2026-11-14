package payload

import (
	"bytes"
	"debug/pe"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// notableImports are APIs that say something about what a PE does.
var notableImports = map[string]string{
	"virtualalloc": "memory", "virtualallocex": "injection", "virtualprotect": "memory", "writeprocessmemory": "injection",
	"createremotethread": "injection", "ntcreatethreadex": "injection", "queueuserapc": "injection", "setthreadcontext": "injection",
	"ntunmapviewofsection": "injection", "openprocess": "process", "createprocessa": "process", "createprocessw": "process",
	"winexec": "process", "shellexecutea": "process", "shellexecutew": "process", "loadlibrarya": "loader",
	"loadlibraryw": "loader", "getprocaddress": "loader", "internetopena": "network", "internetopenw": "network",
	"internetopenurla": "network", "internetopenurlw": "network", "internetconnecta": "network", "internetconnectw": "network",
	"httpsendrequesta": "network", "httpsendrequestw": "network", "internetreadfile": "network", "urldownloadtofilea": "network",
	"urldownloadtofilew": "network", "winhttpopen": "network", "winhttpconnect": "network", "wsastartup": "network",
	"connect": "network", "send": "network", "recv": "network", "regsetvalueexa": "persistence", "regsetvalueexw": "persistence",
	"regcreatekeyexa": "persistence", "regcreatekeyexw": "persistence", "createservicea": "persistence",
	"createservicew": "persistence", "cryptencrypt": "crypto", "cryptdecrypt": "crypto", "bcryptencrypt": "crypto",
	"isdebuggerpresent": "anti-analysis", "checkremotedebuggerpresent": "anti-analysis", "setwindowshookexa": "keylogging",
	"setwindowshookexw": "keylogging", "getasynckeystate": "keylogging", "adjusttokenprivileges": "privileges",
}

var peSubsystems = map[uint16]string{1: "native", 2: "GUI", 3: "console", 9: "Windows CE", 10: "EFI"}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var n [256]float64
	for _, c := range b {
		n[c]++
	}
	e := 0.0
	for _, c := range n {
		if c > 0 {
			p := c / float64(len(b))
			e -= p * math.Log2(p)
		}
	}
	return e
}

// describePE parses PE headers, sections and imports.
func describePE(b []byte) (string, []string) {
	f, err := pe.NewFile(bytes.NewReader(b))
	if err != nil {
		return "PE (MZ header, unparsable: " + err.Error() + ")", nil
	}
	defer f.Close()
	kind := "PE32 executable"
	var entry uint32
	var subsystem uint16
	var dirs []pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entry, subsystem, dirs = oh.AddressOfEntryPoint, oh.Subsystem, oh.DataDirectory[:oh.NumberOfRvaAndSizes]
	case *pe.OptionalHeader64:
		kind = "PE32+ executable"
		entry, subsystem, dirs = oh.AddressOfEntryPoint, oh.Subsystem, oh.DataDirectory[:oh.NumberOfRvaAndSizes]
	}
	if f.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		kind = strings.Replace(kind, "executable", "DLL", 1)
	}
	if len(dirs) > 14 && dirs[14].VirtualAddress != 0 {
		kind += " (.NET)"
	}
	facts := []string{fmt.Sprintf("machine=0x%04x", f.Machine)}
	if s, ok := peSubsystems[subsystem]; ok {
		facts = append(facts, "subsystem="+s)
	}
	facts = append(facts, fmt.Sprintf("entry_point=0x%x", entry))
	if f.TimeDateStamp != 0 {
		facts = append(facts, "compiled="+time.Unix(int64(f.TimeDateStamp), 0).UTC().Format(time.RFC3339))
	}
	var secs []string
	end := uint32(0)
	for _, s := range f.Sections {
		data, _ := s.Data()
		flags := ""
		if s.Characteristics&0x20000000 != 0 {
			flags += "X"
		}
		if s.Characteristics&0x80000000 != 0 {
			flags += "W"
		}
		note := ""
		if strings.Contains(flags, "X") && strings.Contains(flags, "W") {
			note = " RWX"
		}
		e := entropy(data)
		if e > 7.2 {
			note += " packed?"
		}
		secs = append(secs, fmt.Sprintf("%s(%d bytes, entropy %.2f%s)", strings.TrimRight(s.Name, "\x00"), s.Size, e, note))
		if s.Offset+s.Size > end {
			end = s.Offset + s.Size
		}
		if strings.HasPrefix(s.Name, "UPX") {
			kind += ", UPX-packed"
		}
	}
	facts = append(facts, "sections="+strings.Join(secs, ", "))
	if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
		facts = append(facts, "imports="+strings.Join(libs, ","))
	}
	if syms, err := f.ImportedSymbols(); err == nil && len(syms) > 0 {
		byCat := map[string][]string{}
		for _, s := range syms {
			fn := s
			if i := strings.Index(s, ":"); i >= 0 {
				fn = s[:i]
			}
			if c, ok := notableImports[strings.ToLower(fn)]; ok {
				byCat[c] = append(byCat[c], fn)
			}
		}
		facts = append(facts, fmt.Sprintf("imported_functions=%d", len(syms)))
		var cats []string
		for c := range byCat {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		for _, c := range cats {
			facts = append(facts, "notable_imports["+c+"]="+strings.Join(byCat[c], ","))
		}
	}
	if end > 0 && int(end) < len(b) {
		facts = append(facts, fmt.Sprintf("overlay=%d bytes after the last section", len(b)-int(end)))
	}
	if i := bytes.Index(b, []byte("RSDS")); i >= 0 && i+24 < len(b) {
		pdb := b[i+24:]
		if j := bytes.IndexByte(pdb, 0); j > 0 && j < 260 {
			facts = append(facts, "pdb="+string(pdb[:j]))
		}
	}
	return kind, facts
}

// Entropy returns the Shannon entropy of b in bits per byte (0-8).
func Entropy(b []byte) float64 { return entropy(b) }
