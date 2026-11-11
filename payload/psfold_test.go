package payload

import "testing"

func TestFoldPowerShellConcat(t *testing.T) {
	tests := []struct {
		name, in, want string
		n              int
	}{
		{"simple", `('ht'+'tp://a'+'.com')`, `('http://a.com')`, 1},
		{"spaces and double quotes", `$x = 'a' + "b" +  'c'`, `$x = 'abc'`, 1},
		{"escaped single quote", `'it''s'+'ok'`, `'it''sok'`, 1},
		{"doubled double quote", `"say ""hi"""+'!'`, `'say "hi"!'`, 1},
		{"harmless backtick", "\"Do`wn\"+'load'", `'Download'`, 1},
		{"interpolation stops chain", `'a'+"$b"+'c'`, `'a'+"$b"+'c'`, 0},
		{"special escape stops chain", "'a'+\"`n\"", "'a'+\"`n\"", 0},
		{"variable stops chain", `'a'+$b+'c'`, `'a'+$b+'c'`, 0},
		{"single literal untouched", `'abc'`, `'abc'`, 0},
		{"two chains", `('a'+'b');('c'+'d')`, `('ab');('cd')`, 2},
		{"comment quotes ignored", "# it's\n'a'+'b'", "# it's\n'ab'", 1},
		{"unterminated", `'a'+'b`, `'a'+'b`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, n := FoldPowerShellConcat(tt.in)
			if got != tt.want || n != tt.n {
				t.Fatalf("got %q (%d), want %q (%d)", got, n, tt.want, tt.n)
			}
		})
	}
}

func FuzzFoldPowerShellConcat(f *testing.F) {
	for _, s := range []string{`('a'+'b')`, `"x$y"+'z'`, "'a'+\"`\"", `'''`, `"`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, n := FoldPowerShellConcat(s)
		if n == 0 && out != s {
			t.Fatal("unchanged input must be returned as-is")
		}
	})
}
