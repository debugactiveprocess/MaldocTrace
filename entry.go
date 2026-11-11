package maldoctrace

import (
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/report"
)

var autoexecNames = map[string]string{
	"document_open": "Document_Open event", "document_close": "Document_Close event",
	"document_beforeclose": "Document_BeforeClose event", "document_new": "Document_New event",
	"documentopen": "DocumentOpen event", "documentchange": "DocumentChange event",
	"newdocument": "NewDocument event", "autoexec": "AutoExec", "autoopen": "AutoOpen",
	"autoexit": "AutoExit", "autoclose": "AutoClose", "autonew": "AutoNew",
	"workbook_open": "Workbook_Open event", "workbook_close": "Workbook_Close event",
	"workbook_activate": "Workbook_Activate event", "workbook_beforeclose": "Workbook_BeforeClose event",
	"auto_open": "Auto_Open", "auto_close": "Auto_Close",
	"worksheet_activate": "Worksheet_Activate event", "worksheet_change": "Worksheet_Change event",
	"worksheet_calculate": "Worksheet_Calculate event",
}

var eventSuffixes = []string{
	"_painted", "_painting", "_gotfocus", "_lostfocus", "_click", "_change", "_resize",
	"_beforenavigate2", "_beforenavigate", "_navigatecomplete2", "_documentcomplete",
	"_downloadbegin", "_downloadcomplete", "_filedownload", "_mousemove", "_mouseenter",
	"_mouseleave", "_layout", "_statustextchange", "_titlechange", "_onconnecting",
	"_followhyperlink", "_open", "_close",
}

func autoexecTrigger(name string) (string, bool) {
	low := strings.ToLower(name)
	if t, ok := autoexecNames[low]; ok {
		return t, true
	}
	for _, s := range eventSuffixes {
		if strings.HasSuffix(low, s) {
			return "ActiveX/event handler ending " + s, true
		}
	}
	return "", false
}

func lineCol(code string, off int) (int, int) {
	line, col := 1, 1
	for i := 0; i < off && i < len(code); i++ {
		if code[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

func firstOf(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func dedupeIOCs(items []report.IOC) []report.IOC {
	seen := map[string]int{}
	var out []report.IOC
	for _, it := range items {
		for j := range it.Occurrences {
			if it.Occurrences[j].Discovery == "" {
				it.Occurrences[j].Discovery = it.Discovery
			}
		}
		key := it.Type + "\x00" + it.Value
		if i, ok := seen[key]; ok {
			out[i].Occurrences = append(out[i].Occurrences, it.Occurrences...)
			continue
		}
		seen[key] = len(out)
		out = append(out, it)
	}
	return out
}
