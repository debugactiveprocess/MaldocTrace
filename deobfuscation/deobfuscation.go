// Package deobfuscation performs static, side-effect-free reconstruction of
// obfuscated VBA strings: constant folding, concatenation, and the safe string
// builtins (Chr/ChrW/StrReverse/Replace/...). It records provenance (module,
// procedure, line, column) for every reconstructed value. Loop-based
// reconstruction is delegated to the emulator (reported as "observed").
package deobfuscation

import (
	"maldoctrace/vba/ast"
)

// Decoded is a statically reconstructed string with its provenance.
type Decoded struct {
	Value  string `json:"value"`
	Kind   string `json:"kind"`
	Method string `json:"method,omitempty"`
	Module string `json:"module,omitempty"`
	Proc   string `json:"proc,omitempty"`
	Line   int    `json:"line,omitempty"`
	Col    int    `json:"col,omitempty"`
}

// DecodeModule walks a module AST and statically reconstructs strings.
func DecodeModule(mod *ast.Module, moduleName string) []Decoded {
	var out []Decoded
	visit := func(proc string) func(ast.Expr) {
		return func(e ast.Expr) {
			// visitChildren invokes the callback on e itself first, so the root
			// expression is folded exactly once.
			visitChildren(e, func(child ast.Expr) {
				if s, ok := Fold(child); ok && len(s) > 0 {
					pp := child.Pos()
					out = append(out, Decoded{Value: s, Kind: "static", Method: Method(child), Module: moduleName, Proc: proc, Line: pp.Line, Col: pp.Col})
				}
			})
		}
	}

	for _, p := range mod.Procs {
		for _, st := range p.Body {
			collectExprs(st, visit(p.Name))
		}
	}
	for _, st := range mod.Body {
		collectExprs(st, visit(""))
	}
	return out
}

// visitChildren walks nested sub-expressions of an expression (call arguments,
// binary operands, parenthesised groups, member targets).
func visitChildren(e ast.Expr, fn func(ast.Expr)) {
	if e == nil {
		return
	}
	fn(e)
	switch x := e.(type) {
	case *ast.Binary:
		visitChildren(x.Left, fn)
		visitChildren(x.Right, fn)
	case *ast.Unary:
		visitChildren(x.X, fn)
	case *ast.Call:
		visitChildren(x.Fn, fn)
		for _, a := range x.Args {
			visitChildren(a, fn)
		}
	case *ast.Member:
		visitChildren(x.Obj, fn)
	case *ast.Index:
		visitChildren(x.Base, fn)
		visitChildren(x.Idx, fn)
	case *ast.ArrayLit:
		for _, el := range x.Elems {
			visitChildren(el, fn)
		}
	case *ast.Paren:
		visitChildren(x.X, fn)
	case *ast.NamedArg:
		visitChildren(x.Value, fn)
	}
}

// collectExprs visits interesting expressions in a statement.
func collectExprs(st ast.Stmt, visit func(ast.Expr)) {
	switch s := st.(type) {
	case *ast.Assign:
		visit(s.RHS)
	case *ast.Set:
		visit(s.RHS)
	case *ast.CallStmt:
		visit(s.CallExpr)
	case *ast.Const:
		visit(s.Val)
	case *ast.Dim:
		if s.Init != nil {
			visit(s.Init)
		}
	case *ast.If:
		for _, b := range s.Branches {
			visit(b.Cond)
			for _, x := range b.Body {
				collectExprs(x, visit)
			}
		}
		for _, x := range s.Else {
			collectExprs(x, visit)
		}
	case *ast.For:
		visit(s.Start)
		visit(s.Stop)
		if s.Step != nil {
			visit(s.Step)
		}
		for _, x := range s.Body {
			collectExprs(x, visit)
		}
	case *ast.ForEach:
		visit(s.In)
		for _, x := range s.Body {
			collectExprs(x, visit)
		}
	case *ast.While:
		visit(s.Cond)
		for _, x := range s.Body {
			collectExprs(x, visit)
		}
	case *ast.DoLoop:
		if s.PreCond != nil {
			visit(s.PreCond)
		}
		if s.PostCond != nil {
			visit(s.PostCond)
		}
		for _, x := range s.Body {
			collectExprs(x, visit)
		}
	case *ast.Select:
		visit(s.Test)
		for _, c := range s.Cases {
			for _, ce := range c.Exprs {
				visit(ce)
			}
			for _, x := range c.Body {
				collectExprs(x, visit)
			}
		}
	case *ast.With:
		visit(s.Obj)
		for _, x := range s.Body {
			collectExprs(x, visit)
		}
	}
}
