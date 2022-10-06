package did

import (
	"encoding/json"
	"testing"
)

// Example10 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-10
const example10 = `{
  "id": "did:example:123456789abcdefghijk"
}`

// Example11 is borrowed from the W3C, excluding syntax errors.
// https://www.w3.org/TR/did-core/#example-did-document-with-a-controller-property
const example11 = `{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:example:123456789abcdefghi",
  "controller": "did:example:bcehfew7h32f32h7af3"
}`

func TestDocSubjectJSON(t *testing.T) {
	var doc Doc
	err := json.Unmarshal([]byte(example10), &doc)
	if err != nil {
		t.Fatal(err)
	}

	const want = "did:example:123456789abcdefghijk"
	if got := doc.Subject.String(); got != want {
		t.Errorf("got subject %q, want %q", got, want)
	}
}

func TestDocControllersJSON(t *testing.T) {
	var doc Doc
	err := json.Unmarshal([]byte(example11), &doc)
	if err != nil {
		t.Fatal(err)
	}

	if n := len(doc.Controllers); n != 1 {
		t.Fatalf("got %d controllers, want 1", n)
	}
	const want = "did:example:bcehfew7h32f32h7af3"
	if got := doc.Controllers[0].String(); got != want {
		t.Errorf("got subject %q, want %q", got, want)
	}
}
