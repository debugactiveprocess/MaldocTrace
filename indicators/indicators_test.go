package indicators

import (
	"reflect"
	"testing"
)

func TestJoinedURLsAreSplit(t *testing.T) {
	var got []string
	for _, f := range Scan(`'http://a.example/x/*https://b.example/y/*ftp://c.example/z'`) {
		if f.Type == "url" {
			got = append(got, f.Value)
		}
	}
	want := []string{"http://a.example/x/", "https://b.example/y/", "ftp://c.example/z"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestSingleURLUnchanged(t *testing.T) {
	f := Scan("see http://a.example/p?q=http%3A x")
	if len(f) == 0 || f[0].Value != "http://a.example/p?q=http%3A" {
		t.Fatalf("%+v", f)
	}
}
