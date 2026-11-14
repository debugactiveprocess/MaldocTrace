package payload

import (
	"strconv"
	"strings"
)

// batchEnv are environment variables a batch script reads from the system;
// they are kept as written instead of expanding to empty.
var batchEnv = map[string]bool{
	"temp": true, "tmp": true, "appdata": true, "localappdata": true, "userprofile": true, "public": true,
	"programdata": true, "allusersprofile": true, "windir": true, "systemroot": true, "systemdrive": true,
	"homedrive": true, "homepath": true, "username": true, "computername": true, "userdomain": true,
	"programfiles": true, "programfiles(x86)": true, "comspec": true, "path": true, "random": true,
	"cd": true, "date": true, "time": true, "errorlevel": true, "processor_architecture": true, "os": true,
}

const maxBatchVarLen = 1 << 16

// DeobfuscateBatch replays the variable assignments of a batch script the
// way cmd.exe expands them, line by line, and returns the command lines it
// would run with every %VAR%, %VAR:~start,len%, %VAR:old=new% and !VAR!
// reference replaced. Droppers build their commands from hundreds of
// one-character "set" lines; the result is what cmd actually executes.
// Assignments, labels and comments are left out; nothing is executed.
func DeobfuscateBatch(text string) string {
	vars := map[string]string{}
	var out strings.Builder
	lines := strings.FieldsFunc(text, func(c rune) bool { return c == '\n' || c == '\r' })
	if len(lines) > 100000 {
		lines = lines[:100000]
	}
	for _, raw := range lines {
		// Trailing blanks are kept: "set s= " assigns a space, the
		// separator droppers splice between command fragments.
		line := strings.TrimLeft(expandBatch(raw, vars, '%'), " 	")
		line = stripCarets(expandBatch(line, vars, '!'))
		low := lowerASCII(line)
		switch {
		case strings.TrimSpace(line) == "", strings.HasPrefix(line, "::"), strings.HasPrefix(line, ":"),
			low == "rem", strings.HasPrefix(low, "rem "), strings.HasPrefix(low, "@rem"):
			continue
		case strings.HasPrefix(low, "set ") || strings.HasPrefix(low, "@set "):
			batchAssign(strings.TrimLeft(line[strings.Index(low, "set ")+4:], " 	"), vars)
			continue
		}
		line = strings.TrimSpace(line)
		if out.Len() > 1<<20 {
			break
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

// batchAssign records "NAME=value" or "\"NAME=value\"" (set /a and /p are
// not evaluated).
func batchAssign(arg string, vars map[string]string) {
	if strings.HasPrefix(arg, "/") {
		return
	}
	if strings.HasPrefix(arg, `"`) {
		arg = arg[1:]
		if i := strings.LastIndexByte(arg, '"'); i >= 0 {
			arg = arg[:i]
		}
	}
	eq := strings.IndexByte(arg, '=')
	if eq <= 0 {
		return
	}
	name := strings.ToLower(arg[:eq])
	val := arg[eq+1:]
	if len(val) > maxBatchVarLen {
		val = val[:maxBatchVarLen]
	}
	if val == "" {
		delete(vars, name)
		return
	}
	vars[name] = val
}

// expandBatch replaces the variable references delimited by d ('%' or '!').
func expandBatch(s string, vars map[string]string, d byte) string {
	if strings.IndexByte(s, d) < 0 {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != d {
			b.WriteByte(c)
			continue
		}
		if d == '%' && i+1 < len(s) && (s[i+1] == '%' || s[i+1] == '~' || s[i+1] >= '0' && s[i+1] <= '9' || s[i+1] == '*') {
			// %% is a literal percent (or a FOR variable); %0-%9, %* and
			// %~dp0 are arguments, kept as written.
			b.WriteByte(c)
			b.WriteByte(s[i+1])
			i++
			continue
		}
		j := strings.IndexByte(s[i+1:], d)
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		ref := s[i+1 : i+1+j]
		v, ok := resolveBatchRef(ref, vars)
		switch {
		case ok:
			b.WriteString(v)
		case batchEnv[strings.ToLower(strings.SplitN(ref, ":", 2)[0])] || d == '!' || strings.ContainsAny(ref, " \t\"<>|&"):
			// System variables stay as written; so do unset !names! (cmd
			// without delayed expansion) and text that cannot be a name.
			if strings.ContainsAny(ref, " \t\"<>|&") {
				b.WriteByte(c)
				continue
			}
			b.WriteByte(d)
			b.WriteString(ref)
			b.WriteByte(d)
		}
		// An unset variable in a batch file expands to nothing.
		i += j + 1
		if b.Len() > 1<<20 {
			break
		}
	}
	return b.String()
}

// resolveBatchRef resolves NAME, NAME:~start[,len] and NAME:old=new.
func resolveBatchRef(ref string, vars map[string]string) (string, bool) {
	name, mod, hasMod := strings.Cut(ref, ":")
	v, ok := vars[strings.ToLower(name)]
	if !ok {
		return "", false
	}
	if !hasMod {
		return v, true
	}
	if strings.HasPrefix(mod, "~") {
		parts := strings.SplitN(mod[1:], ",", 2)
		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return "", false
		}
		n := len(v)
		if start < 0 {
			start += n
		}
		start = max(0, min(start, n))
		end := n
		if len(parts) == 2 {
			l, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return "", false
			}
			if l < 0 {
				end = n + l
			} else {
				end = start + l
			}
			end = max(start, min(end, n))
		}
		return v[start:end], true
	}
	old, repl, ok := strings.Cut(mod, "=")
	if !ok || old == "" {
		return v, true
	}
	if strings.HasPrefix(old, "*") {
		// *old=new replaces everything up to the first match.
		k := strings.Index(lowerASCII(v), lowerASCII(old[1:]))
		if k < 0 {
			return v, true
		}
		return repl + v[k+len(old)-1:], true
	}
	return replaceFold(v, old, repl), true
}

func replaceFold(s, old, repl string) string {
	var b strings.Builder
	// cmd compares case-insensitively; ASCII folding keeps byte offsets
	// valid on any input (strings.ToLower can change lengths).
	ls, lo := lowerASCII(s), lowerASCII(old)
	for {
		k := strings.Index(ls, lo)
		if k < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:k])
		b.WriteString(repl)
		s, ls = s[k+len(old):], ls[k+len(old):]
	}
}

// stripCarets removes the ^ escape characters outside double quotes.
func stripCarets(s string) string {
	if strings.IndexByte(s, '^') < 0 {
		return s
	}
	var b strings.Builder
	quoted := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			quoted = !quoted
		}
		if c == '^' && !quoted && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
