package extractor

import (
	"strings"
	"testing"
)

func TestWordXMLText(t *testing.T) {
	x := `<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>Hello </w:t></w:r><w:r><w:tab/><w:t>world</w:t></w:r></w:p><w:p><w:r><w:t>TVqQ</w:t></w:r></w:p></w:body></w:document>`
	got, err := wordXMLText(strings.NewReader(x))
	if err != nil || got != "Hello \tworld\rTVqQ\r" {
		t.Fatalf("%q %v", got, err)
	}
}
