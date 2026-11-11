package runtime

import (
	"strconv"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/lexer"
)

func builtinMid(rt *Interp, args []Value, _ lexer.Pos) Value {
	s := argStr(args, 0)
	start, _ := argInt(args, 1)
	ln := int64(-1)
	if v, ok := argInt(args, 2); ok {
		ln = v
	}
	rr := []rune(s)
	if start < 1 {
		start = 1
	}
	start--
	if start >= int64(len(rr)) {
		return VString("")
	}
	end := int64(len(rr))
	if ln >= 0 && start+ln < end {
		end = start + ln
	}
	return VString(string(rr[start:end]))
}

func builtinLeft(rt *Interp, args []Value, _ lexer.Pos) Value {
	s := argStr(args, 0)
	n, _ := argInt(args, 1)
	return VString(string(leftRunes([]rune(s), n)))
}

func leftRunes(rr []rune, n int64) []rune {
	if n < 0 {
		return nil
	}
	if int64(len(rr)) < n {
		n = int64(len(rr))
	}
	return rr[:n]
}

func builtinRight(rt *Interp, args []Value, _ lexer.Pos) Value {
	s := argStr(args, 0)
	n, _ := argInt(args, 1)
	rr := []rune(s)
	if n < 0 {
		return VString("")
	}
	if int64(len(rr)) < n {
		n = int64(len(rr))
	}
	return VString(string(rr[int64(len(rr))-n:]))
}

func builtinLen(rt *Interp, args []Value, _ lexer.Pos) Value {
	return VInt(int64(len([]rune(argStr(args, 0)))))
}

func builtinTrim(rt *Interp, args []Value, _ lexer.Pos) Value {
	return VString(strings.TrimSpace(argStr(args, 0)))
}
func builtinLTrim(rt *Interp, args []Value, _ lexer.Pos) Value {
	return VString(strings.TrimLeft(argStr(args, 0), " \t\r\n"))
}
func builtinRTrim(rt *Interp, args []Value, _ lexer.Pos) Value {
	return VString(strings.TrimRight(argStr(args, 0), " \t\r\n"))
}
func builtinLCase(rt *Interp, args []Value, _ lexer.Pos) Value {
	return VString(strings.ToLower(argStr(args, 0)))
}
func builtinUCase(rt *Interp, args []Value, _ lexer.Pos) Value {
	return VString(strings.ToUpper(argStr(args, 0)))
}

func builtinInStr(rt *Interp, args []Value, _ lexer.Pos) Value {
	start := int64(1)
	idx := 0
	if len(args) >= 3 {
		if v, ok := args[0].CoerceInt(); ok && args[0].Kind != KindString {
			start = v
			idx = 1
		}
	}
	s := argStr(args, idx)
	sub := argStr(args, idx+1)
	rr := []rune(s)
	if start < 1 {
		start = 1
	}
	if start > int64(len(rr)) {
		return VInt(0)
	}
	pos := strings.Index(string(rr[start-1:]), sub)
	if pos < 0 {
		return VInt(0)
	}
	return VInt(start + int64(pos))
}

func builtinCStr(rt *Interp, args []Value, _ lexer.Pos) Value {
	if len(args) == 0 {
		return VString("")
	}
	return VString(args[0].CoerceString())
}

func builtinCInt(rt *Interp, args []Value, _ lexer.Pos) Value {
	n, ok := args[0].CoerceInt()
	if !ok {
		return VError(13)
	}
	return VInt(n)
}
func builtinCLng(rt *Interp, args []Value, _ lexer.Pos) Value {
	n, ok := args[0].CoerceInt()
	if !ok {
		return VError(13)
	}
	return VInt(n)
}
func builtinCByte(rt *Interp, args []Value, _ lexer.Pos) Value {
	n, ok := args[0].CoerceInt()
	if !ok {
		return VError(13)
	}
	if n < 0 {
		n += 256
	}
	return VInt(n & 0xFF)
}
func builtinCDbl(rt *Interp, args []Value, _ lexer.Pos) Value {
	f, ok := args[0].CoerceFloat()
	if !ok {
		return VError(13)
	}
	return VFloat(f)
}
func builtinCBool(rt *Interp, args []Value, _ lexer.Pos) Value {
	return VBool(args[0].Truthy())
}

func builtinVal(rt *Interp, args []Value, _ lexer.Pos) Value {
	s := strings.TrimSpace(argStr(args, 0))
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	j := i
	if j < len(s) && (s[j] == '+' || s[j] == '-' || s[j] == '.') {
		j++
	}
	for j < len(s) && isDigitByte(s[j]) {
		j++
	}
	if j < len(s) && s[j] == '.' {
		j++
		for j < len(s) && isDigitByte(s[j]) {
			j++
		}
	}
	num := s[i:j]
	if num == "" || num == "+" || num == "-" || num == "." {
		return VInt(0)
	}
	if n, err := strconv.ParseFloat(num, 64); err == nil {
		return VFloat(n)
	}
	return VInt(0)
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }
