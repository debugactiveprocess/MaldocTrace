package payload

import "strings"

// psLiteral is one PowerShell string literal located in a script.
type psLiteral struct {
	start, end int    // byte range in the source, end exclusive
	value      string // decoded value
	constant   bool   // false for double-quoted strings with $ interpolation
}

// scanPSLiteral parses a single- or double-quoted PowerShell string starting
// at s[i]. It returns ok=false when the literal is unterminated.
func scanPSLiteral(s string, i int) (psLiteral, bool) {
	q := s[i]
	var b strings.Builder
	lit := psLiteral{start: i, constant: true}
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		if q == '\'' {
			if c == '\'' {
				if j+1 < len(s) && s[j+1] == '\'' {
					b.WriteByte('\'')
					j++
					continue
				}
				lit.end, lit.value = j+1, b.String()
				return lit, true
			}
			b.WriteByte(c)
			continue
		}
		switch c {
		case '`':
			if j+1 >= len(s) {
				return lit, false
			}
			j++
			switch s[j] {
			case '0', 'a', 'b', 'e', 'f', 'n', 'r', 't', 'v', 'u':
				// Escape sequences with a non-literal meaning: keep the
				// expression as written rather than guess its value.
				lit.constant = false
			default:
				b.WriteByte(s[j])
			}
		case '$':
			lit.constant = false
			b.WriteByte(c)
		case '"':
			if j+1 < len(s) && s[j+1] == '"' {
				b.WriteByte('"')
				j++
				continue
			}
			lit.end, lit.value = j+1, b.String()
			return lit, true
		default:
			b.WriteByte(c)
		}
	}
	return lit, false
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// FoldPowerShellConcat statically folds chains of constant string literals
// joined with '+' (for example ('ht'+'tp:'+'//x'+'.com')) into one
// single-quoted literal. Only literal-only chains are folded; variables,
// interpolated strings and escapes with special meaning stop a chain, so the
// result never contains a value the script could not have produced. It
// returns the rewritten script and the number of chains folded. The input is
// never executed.
func FoldPowerShellConcat(s string) (string, int) {
	if len(s) > MaxPayloadBytes {
		return s, 0
	}
	var out strings.Builder
	folded := 0
	last := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '#' {
			// Skip line comments so quotes inside them do not desynchronise.
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		}
		if c != '\'' && c != '"' {
			continue
		}
		first, ok := scanPSLiteral(s, i)
		if !ok {
			break
		}
		if !first.constant {
			i = first.end - 1
			continue
		}
		parts := []psLiteral{first}
		end := first.end
		for {
			j := skipSpace(s, end)
			if j >= len(s) || s[j] != '+' {
				break
			}
			j = skipSpace(s, j+1)
			if j >= len(s) || (s[j] != '\'' && s[j] != '"') {
				break
			}
			next, ok := scanPSLiteral(s, j)
			if !ok || !next.constant {
				break
			}
			parts = append(parts, next)
			end = next.end
		}
		if len(parts) > 1 {
			var v strings.Builder
			for _, p := range parts {
				v.WriteString(p.value)
			}
			out.WriteString(s[last:first.start])
			out.WriteString("'" + strings.ReplaceAll(v.String(), "'", "''") + "'")
			last = end
			folded++
		}
		i = end - 1
	}
	if folded == 0 {
		return s, 0
	}
	out.WriteString(s[last:])
	return out.String(), folded
}
