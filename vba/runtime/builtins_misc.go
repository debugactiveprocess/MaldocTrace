package runtime

import (
	"math"
	"strconv"
	"strings"

	"github.com/debugactiveprocess/MaldocTrace/vba/lexer"
)

func builtinArray(rt *Interp, args []Value, _ lexer.Pos) Value {
	return VArray(args)
}

func builtinUBound(rt *Interp, args []Value, _ lexer.Pos) Value {
	if len(args) > 0 && args[0].Kind == KindArray {
		return VInt(int64(len(args[0].Arr) - 1))
	}
	return VInt(0)
}

func builtinLBound(rt *Interp, args []Value, _ lexer.Pos) Value { return VInt(0) }

func builtinString(rt *Interp, args []Value, _ lexer.Pos) Value {
	n, _ := argInt(args, 0)
	if n < 0 || n > 1<<20 {
		return VString("")
	}
	var c string
	if len(args) > 1 {
		if args[1].Kind == KindString && args[1].Str != "" {
			c = string([]rune(args[1].Str)[0])
		} else if ni, ok := args[1].CoerceInt(); ok {
			c = string(rune(ni))
		}
	}
	return VString(strings.Repeat(c, int(n)))
}

func builtinSpace(rt *Interp, args []Value, _ lexer.Pos) Value {
	n, _ := argInt(args, 0)
	if n < 0 || n > 1<<20 {
		return VString("")
	}
	return VString(strings.Repeat(" ", int(n)))
}

func builtinAbs(rt *Interp, args []Value, _ lexer.Pos) Value {
	if f, ok := args[0].CoerceFloat(); ok {
		return VFloat(math.Abs(f))
	}
	return VUnknown
}

func builtinSgn(rt *Interp, args []Value, _ lexer.Pos) Value {
	f, ok := args[0].CoerceFloat()
	if !ok {
		return VUnknown
	}
	if f > 0 {
		return VInt(1)
	}
	if f < 0 {
		return VInt(-1)
	}
	return VInt(0)
}

func builtinInt(rt *Interp, args []Value, _ lexer.Pos) Value {
	f, ok := args[0].CoerceFloat()
	if !ok {
		return VUnknown
	}
	return VInt(int64(math.Floor(f)))
}

func builtinFix(rt *Interp, args []Value, _ lexer.Pos) Value {
	f, ok := args[0].CoerceFloat()
	if !ok {
		return VUnknown
	}
	return VInt(int64(f))
}

func builtinHex(rt *Interp, args []Value, _ lexer.Pos) Value {
	n, ok := args[0].CoerceInt()
	if !ok {
		return VUnknown
	}
	return VString(strings.ToUpper(strconv.FormatInt(n, 16)))
}

func builtinOct(rt *Interp, args []Value, _ lexer.Pos) Value {
	n, ok := args[0].CoerceInt()
	if !ok {
		return VUnknown
	}
	return VString(strconv.FormatInt(n, 8))
}

func builtinStr(rt *Interp, args []Value, _ lexer.Pos) Value {
	f, ok := args[0].CoerceFloat()
	if !ok {
		return VUnknown
	}
	return VString(strconv.FormatFloat(f, 'g', -1, 64))
}

func builtinIIf(rt *Interp, args []Value, _ lexer.Pos) Value {
	if len(args) < 3 {
		return VNull
	}
	if args[0].Truthy() {
		return args[1]
	}
	return args[2]
}

func builtinCreateObject(rt *Interp, args []Value, pos lexer.Pos) Value {
	progID := argStr(args, 0)
	rt.event(&Event{Type: "create_object", Line: pos.Line, Col: pos.Col, Resolved: []string{progID}, Simulated: true})
	if len(args) == 0 || args[0].IsUnknown() {
		return NewUnknown("CreateObject identifier unresolved")
	}
	if rt.host != nil {
		return rt.host.CreateObject(progID)
	}
	return VNothing
}

func builtinGetObject(rt *Interp, args []Value, pos lexer.Pos) Value {
	progID := argStr(args, 0)
	rt.event(&Event{Type: "get_object", Line: pos.Line, Col: pos.Col, Resolved: []string{progID}, Simulated: true})
	if len(args) == 0 || args[0].IsUnknown() {
		return NewUnknown("GetObject identifier unresolved")
	}
	if rt.host != nil {
		return rt.host.GetObject(progID)
	}
	return VNothing
}

func builtinShell(rt *Interp, args []Value, pos lexer.Pos) Value {
	cmd := argStr(args, 0)
	rt.event(&Event{Type: "shell", Line: pos.Line, Col: pos.Col, Resolved: []string{cmd}, Simulated: true})
	return VInt(0) // simulated PID
}

func builtinEnviron(rt *Interp, args []Value, pos lexer.Pos) Value {
	name := argStr(args, 0)
	rt.event(&Event{Type: "environ_read", Line: pos.Line, Col: pos.Col, Resolved: []string{name}, Simulated: true})
	return VString("")
}

func builtinDoEvents(rt *Interp, args []Value, _ lexer.Pos) Value { return VEmpty }

func builtinMsgBox(rt *Interp, args []Value, _ lexer.Pos) Value { return VInt(1) }

// builtins maps lower-cased function names to their implementations.
var builtins = map[string]builtinFunc{
	"chr": builtinChr, "chrw": builtinChrW, "chrb": builtinChr,
	"asc": builtinAsc, "ascw": builtinAscW, "ascb": builtinAsc,
	"strreverse": builtinStrReverse, "replace": builtinReplace,
	"split": builtinSplit, "join": builtinJoin, "mid": builtinMid,
	"mid$": builtinMid, "midb": builtinMid,
	"left": builtinLeft, "left$": builtinLeft, "right": builtinRight, "right$": builtinRight,
	"len": builtinLen, "lenb": builtinLen,
	"trim": builtinTrim, "ltrim": builtinLTrim, "rtrim": builtinRTrim,
	"lcase": builtinLCase, "ucase": builtinUCase, "instr": builtinInStr,
	"cstr": builtinCStr, "cint": builtinCInt, "clng": builtinCLng,
	"cbyte": builtinCByte, "cdbl": builtinCDbl, "cbool": builtinCBool,
	"csng": builtinCDbl, "ccur": builtinCDbl, "val": builtinVal,
	"array": builtinArray, "ubound": builtinUBound, "lbound": builtinLBound,
	"string": builtinString, "string$": builtinString, "space": builtinSpace, "space$": builtinSpace,
	"abs": builtinAbs, "sgn": builtinSgn, "int": builtinInt, "fix": builtinFix,
	"hex": builtinHex, "hex$": builtinHex, "oct": builtinOct, "oct$": builtinOct,
	"str": builtinStr, "iif": builtinIIf,
	"createobject": builtinCreateObject, "getobject": builtinGetObject,
	"shell": builtinShell, "environ": builtinEnviron, "environ$": builtinEnviron,
	"doevents": builtinDoEvents, "msgbox": builtinMsgBox,
}
