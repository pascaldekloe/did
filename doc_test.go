package did

import (
	"encoding/json"
	"testing"
)

func TestDocSubjectJSON(t *testing.T) {
	const sample = `{
  "id": "did:example:123456789abcdefghijk"
}`

	var doc Doc
	err := json.Unmarshal([]byte(sample), &doc)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Subject.Method != "example" {
		t.Errorf("got subject method %q, want example", doc.Subject.Method)
	}
	if doc.Subject.SpecID != "123456789abcdefghijk" {
		t.Errorf("got method-specific identifier %q, want 123456789abcdefghijk", doc.Subject.SpecID)
	}
}
