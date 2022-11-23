package did_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/pascaldekloe/did"
)

// Example9 is borrowed from the W3C, excluding comments and syntax errors.
// https://www.w3.org/TR/did-core/#example-an-example-of-a-relative-did-url
const example9 = `{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:example:123456789abcdefghi",
  "verificationMethod": [{
    "id": "did:example:123456789abcdefghi#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  }],
  "authentication": [
    "#key-1"
  ]
}`

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

// Example15 is borrowed from the W3C, excluding comments.
// https://www.w3.org/TR/did-core/#example-authentication-property-containing-three-verification-methods
const example15 = `{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:example:123456789abcdefghi",
  "authentication": [
    "did:example:123456789abcdefghi#keys-1",
    {
      "id": "did:example:123456789abcdefghi#keys-2",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    }
  ]
}`

func TestDocSubjectJSON(t *testing.T) {
	var doc did.Document
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
	var doc did.Document
	err := json.Unmarshal([]byte(example11), &doc)
	if err != nil {
		t.Fatal(err)
	}

	const want = "did:example:bcehfew7h32f32h7af3"
	if len(doc.Controllers) != 1 || !doc.Controllers.Contains(want) {
		t.Errorf("got controllers %q, want [%q]", doc.Controllers, want)
	}
}

func ExampleDocument_VerificationMethodOrNil_relativeURL() {
	var doc did.Document
	err := json.Unmarshal([]byte(example9), &doc)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("referenced verification-methods:", doc.Authentication.URIRefs)
	if len(doc.Authentication.URIRefs) != 1 {
		return
	}

	m := doc.VerificationMethodOrNil(doc.Authentication.URIRefs[0])
	if m == nil {
		fmt.Println("referenced verification-method not found")
		return
	}
	fmt.Println("public key:", m.AdditionalString("publicKeyMultibase"))
	// Output:
	// referenced verification-methods: [#key-1]
	// public key: zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV
}

func TestVerificationRelationshipUnmarshalJSON(t *testing.T) {
	var doc did.Document
	err := json.Unmarshal([]byte(example15), &doc)
	if err != nil {
		t.Fatal(err)
	}

	if doc.Authentication == nil {
		t.Fatal("Doc Authentication absent")
	}

	const want1 = "did:example:123456789abcdefghi#keys-1"
	if n := len(doc.Authentication.URIRefs); n != 1 {
		t.Errorf("got %d referenced methods, want 1", n)
	} else if got := doc.Authentication.URIRefs[0]; got != want1 {
		t.Errorf("got referenced method %q, want %q", got, want1)
	}

	const want2 = "did:example:123456789abcdefghi#keys-2"
	if n := len(doc.Authentication.Methods); n != 1 {
		t.Errorf("got %d embedded methods, want 1", n)
	} else if got := doc.Authentication.Methods[0].ID.String(); got != want2 {
		t.Errorf("got embedded method %q, want %q", got, want2)
	}
}
