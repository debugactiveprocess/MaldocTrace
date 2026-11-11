package ast

type Assign struct {
	At
	LHS Expr
	RHS Expr
}

func (s *Assign) stmtNode() {}

type Set struct {
	At
	LHS Expr
	RHS Expr
}

func (s *Set) stmtNode() {}

type CallStmt struct {
	At
	CallExpr Expr
}

func (s *CallStmt) stmtNode() {}

type Dim struct {
	At
	Name   string
	Bounds []Expr
	Type   string
	Init   Expr
	ReDim  bool
	Static bool
}

func (s *Dim) stmtNode() {}

type Const struct {
	At
	Name string
	Type string
	Val  Expr
}

func (s *Const) stmtNode() {}

type IfBranch struct {
	Cond Expr
	Body []Stmt
}

type If struct {
	At
	Branches []IfBranch
	Else     []Stmt
}

func (s *If) stmtNode() {}

type CaseClause struct {
	Exprs []Expr
	Body  []Stmt
}

type Select struct {
	At
	Test  Expr
	Cases []CaseClause
}

func (s *Select) stmtNode() {}

type For struct {
	At
	Var   string
	Start Expr
	Stop  Expr
	Step  Expr
	Body  []Stmt
}

func (s *For) stmtNode() {}

type ForEach struct {
	At
	Var  string
	In   Expr
	Body []Stmt
}

func (s *ForEach) stmtNode() {}

type DoLoop struct {
	At
	PreCond  Expr
	PostCond Expr
	PreWhile bool // true = While, false = Until
	Body     []Stmt
}

func (s *DoLoop) stmtNode() {}

type While struct {
	At
	Cond Expr
	Body []Stmt
}

func (s *While) stmtNode() {}

type Exit struct {
	At
	What string
}

func (s *Exit) stmtNode() {}

type OnError struct {
	At
	ResumeNext bool
	GotoZero   bool
	GotoLabel  string
}

func (s *OnError) stmtNode() {}

type With struct {
	At
	Obj  Expr
	Body []Stmt
}

func (s *With) stmtNode() {}

type End struct{ At }

func (s *End) stmtNode() {}

type Stop struct{ At }

func (s *Stop) stmtNode() {}

type Goto struct {
	At
	Label string
}

func (s *Goto) stmtNode() {}

type Label struct {
	At
	Name string
}

func (s *Label) stmtNode() {}

type Resume struct {
	At
	Next  bool
	Label string
}

func (s *Resume) stmtNode() {}

// Noop records a recognised-but-unimplemented statement for diagnostics.
type Noop struct {
	At
	Text string
}

func (s *Noop) stmtNode() {}
