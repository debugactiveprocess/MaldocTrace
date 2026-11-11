// Package ast defines the abstract syntax tree nodes for VBA modules.
package ast

import "maldoctrace/vba/lexer"

type Node interface{ Pos() lexer.Pos }

// At embeds a source position.
type At struct{ P lexer.Pos }

func (a At) Pos() lexer.Pos { return a.P }

type Expr interface {
	Node
	exprNode()
}

type Stmt interface {
	Node
	stmtNode()
}

// Module is a parsed VBA module.
type Module struct {
	Procs  []*Proc
	Decls  []*Declare
	Body   []Stmt
	Errors []*lexer.SyntaxError
}

type ProcKind int

const (
	ProcSub ProcKind = iota
	ProcFunction
	ProcProperty
)

type Proc struct {
	At
	Name       string
	Kind       ProcKind
	Params     []*Param
	ReturnType string
	Body       []Stmt
}

type Param struct {
	At
	Name       string
	Type       string
	ByRef      bool
	ByVal      bool
	Optional   bool
	ParamArray bool
}

type Declare struct {
	At
	Name    string
	Lib     string
	Alias   string
	PtrSafe bool
	IsFunc  bool
	Return  string
	Params  []*Param
}

type Ident struct {
	At
	Name string
}

func (e *Ident) exprNode() {}

type NumLit struct {
	At
	Text    string
	Int     int64
	IsFloat bool
	Float   float64
}

func (e *NumLit) exprNode() {}

type StrLit struct {
	At
	Value string
}

func (e *StrLit) exprNode() {}

type BoolLit struct {
	At
	Value bool
}

func (e *BoolLit) exprNode() {}

type NullLit struct{ At }

func (e *NullLit) exprNode() {}

type NothingLit struct{ At }

func (e *NothingLit) exprNode() {}

type EmptyLit struct{ At }

func (e *EmptyLit) exprNode() {}

type Unary struct {
	At
	Op string
	X  Expr
}

func (e *Unary) exprNode() {}

type Binary struct {
	At
	Op          string
	Left, Right Expr
}

func (e *Binary) exprNode() {}

type Call struct {
	At
	Fn   Expr
	Args []Expr
}

func (e *Call) exprNode() {}

type Member struct {
	At
	Obj  Expr
	Name string
}

func (e *Member) exprNode() {}

type Index struct {
	At
	Base Expr
	Idx  Expr
}

func (e *Index) exprNode() {}

type ArrayLit struct {
	At
	Elems []Expr
}

func (e *ArrayLit) exprNode() {}

// NamedArg is a named call argument (Name:=Value).
type NamedArg struct {
	At
	Name  string
	Value Expr
}

func (e *NamedArg) exprNode() {}

type Paren struct {
	At
	X Expr
}

func (e *Paren) exprNode() {}

type NewExpr struct {
	At
	Name string
}

func (e *NewExpr) exprNode() {}
