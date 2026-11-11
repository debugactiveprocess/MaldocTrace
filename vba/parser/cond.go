package parser

import (
	"strconv"
	"strings"
)

// condCompile resolves #If/#ElseIf/#Else/#End If directives and #Const.
// VBA7/Win64/VBA6 are True on this host profile and Mac is False; other
// identifiers are unknown and their block is kept, with a diagnostic.
func condCompile(code string) (string, []string) {
	norm := strings.ReplaceAll(strings.ReplaceAll(code, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(norm, "\n")
	out := make([]string, len(lines))
	var diags []string
	consts := map[string]bool{"vba7": true, "win64": true, "vba6": true, "mac": false, "true": true, "false": false}
	pos := 0
	up := func(s string) string { return strings.TrimSpace(strings.ToUpper(s)) }

	var processBlock func(active bool)
	processBlock = func(active bool) {
		taken := false
		for pos < len(lines) {
			line := lines[pos]
			u := up(line)
			var cond string
			var isCond, isElse bool
			tl := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(u, "#IF "):
				cond = strings.TrimSpace(tl[4:])
				isCond = true
			case strings.HasPrefix(u, "#ELSEIF "):
				cond = strings.TrimSpace(tl[8:])
				isCond = true
			case u == "#ELSE":
				isElse = true
			case u == "#END IF" || u == "#ENDIF":
				pos++
				return
			default:
				return
			}
			armActive := false
			if isCond {
				c := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(cond), "Then"))
				val, known := evalGuard(c, consts)
				armActive = active && !taken && known && val
				if known && val {
					taken = true
				} else if !known {
					taken = true
					diags = append(diags, "unresolved conditional-compilation condition: "+strings.TrimSpace(line))
				}
			} else if isElse {
				armActive = active && !taken
				taken = true
			}
			pos++
			for pos < len(lines) {
				l2 := lines[pos]
				u2 := up(l2)
				if strings.HasPrefix(u2, "#IF ") {
					processBlock(armActive)
					continue
				}
				if strings.HasPrefix(u2, "#ELSEIF ") || u2 == "#ELSE" || u2 == "#END IF" || u2 == "#ENDIF" {
					break
				}
				if strings.HasPrefix(u2, "#CONST ") {
					handleConst(l2, consts)
					pos++
					continue
				}
				if armActive {
					out[pos] = l2
				}
				pos++
			}
		}
	}

	for pos < len(lines) {
		line := lines[pos]
		u := up(line)
		switch {
		case strings.HasPrefix(u, "#IF "):
			processBlock(true)
		case strings.HasPrefix(u, "#CONST "):
			handleConst(line, consts)
			pos++
		case u == "#ELSE" || u == "#END IF" || u == "#ENDIF" || strings.HasPrefix(u, "#ELSEIF "):
			pos++
		default:
			out[pos] = line
			pos++
		}
	}
	return strings.Join(out, "\n"), diags
}

func handleConst(line string, consts map[string]bool) {
	s := strings.TrimSpace(line)
	for _, p := range []string{"#Const ", "#const "} {
		if strings.HasPrefix(s, p) {
			s = s[len(p):]
			break
		}
	}
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 {
		return
	}
	name := strings.ToLower(strings.TrimSpace(parts[0]))
	val := strings.TrimSpace(parts[1])
	switch strings.ToLower(val) {
	case "true":
		consts[name] = true
	case "false":
		consts[name] = false
	default:
		if n, err := strconv.ParseInt(val, 0, 64); err == nil {
			consts[name] = n != 0
		} else {
			consts[name] = false
		}
	}
}
