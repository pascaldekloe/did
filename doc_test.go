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

	const want = "did:example:123456789abcdefghijk"
	if got := doc.Subject.String(); got != want {
		t.Errorf("got subject %q, want %q", got, want)
	}
}
