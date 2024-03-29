package did_test

import (
	"bytes"
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

// Example12 is borrowed from the W3C, excluding comments and syntax errors.
// https://www.w3.org/TR/did-core/#example-example-verification-method-structure
const example12 = `{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:example:123456789abcdefghi",
  "verificationMethod": [{
    "id": "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
    "type": "JsonWebKey2020",
    "controller": "did:example:123",
    "publicKeyJwk": {
      "crv": "Ed25519",
      "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ",
      "kty": "OKP",
      "kid": "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"
    }
  }, {
    "id": "did:example:123456789abcdefghi#keys-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:example:pqrstuvwxyz0987654321",
    "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  }]
}`

// Example13 is borrowed from the W3C, excluding comments and syntax errors.
// https://www.w3.org/TR/did-core/#example-various-verification-method-types
const example13 = `{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:example:123456789abcdefghi",
  "verificationMethod": [{
    "id": "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
    "type": "JsonWebKey2020",
    "controller": "did:example:123",
    "publicKeyJwk": {
      "crv": "Ed25519",
      "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ",
      "kty": "OKP",
      "kid": "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"
    }
  }, {
    "id": "did:example:123456789abcdefghi#keys-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:example:pqrstuvwxyz0987654321",
    "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  }]
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

// Example20 is borrowed from the W3C, excluding comments.
// https://www.w3.org/TR/did-core/#example-usage-of-the-service-property
const example20 = `{
  "service": [{
    "id":"did:example:123#linked-domain",
    "type": "LinkedDomains",
    "serviceEndpoint": "https://bar.example.com"
  }]
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
	if len(doc.Controllers) != 1 || !doc.Controllers.ContainsString(want) {
		t.Errorf("got controllers %q, want [%q]", doc.Controllers, want)
	}
}

func ExampleDocument_VerificationMethodRefs_relativeURL() {
	var doc did.Document
	err := json.Unmarshal([]byte(example9), &doc)
	if err != nil {
		fmt.Println(err)
		return
	}

	perURI, notFound := doc.VerificationMethodRefs()
	if len(notFound) != 0 {
		fmt.Println("references not found:", notFound)
	}

	authRefs := doc.Authentication.URIRefs
	fmt.Println("referenced verification-methods:", authRefs)
	if len(authRefs) != 0 {
		m := perURI[authRefs[0]]
		if m != nil {
			fmt.Println("public key:", m.AdditionalString("publicKeyMultibase"))
		}
	}
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
	} else if got := doc.Authentication.URIRefs[0].String(); got != want1 {
		t.Errorf("got referenced method %q, want %q", got, want1)
	}

	const want2 = "did:example:123456789abcdefghi#keys-2"
	if n := len(doc.Authentication.Methods); n != 1 {
		t.Errorf("got %d embedded methods, want 1", n)
	} else if got := doc.Authentication.Methods[0].ID.String(); got != want2 {
		t.Errorf("got embedded method %q, want %q", got, want2)
	}
}

func ExampleVerificationMethod_jSON() {
	var doc did.Document
	err := json.Unmarshal([]byte(example12), &doc)
	if err != nil {
		fmt.Println(err)
		return
	}

	if l := len(doc.VerificationMethods); l != 2 {
		fmt.Println("verification method count:", l)
		return
	}
	method0 := doc.VerificationMethods[0]
	fmt.Printf("• %s has JWK %s\n", &method0.ID, method0.Additional["publicKeyJwk"])
	method1 := doc.VerificationMethods[1]
	fmt.Printf("• %s has multibase %s\n", &method1.ID, method1.AdditionalString("publicKeyMultibase"))
	// Output:
	// • did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A has JWK {
	//       "crv": "Ed25519",
	//       "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ",
	//       "kty": "OKP",
	//       "kid": "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"
	//     }
	// • did:example:123456789abcdefghi#keys-1 has multibase zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV
}

func TestVerificationMethodMarshalJSON(t *testing.T) {
	var want bytes.Buffer
	// normalize sample (in sync with json.Marshal output)
	err := json.Compact(&want, []byte(example13))
	if err != nil {
		t.Fatal("sample preparation:", err)
	}

	var doc struct {
		Context []string `json:"@context"`
		did.Document
	}
	doc.Context = []string{
		"https://www.w3.org/ns/did/v1",
		"https://w3id.org/security/suites/jws-2020/v1",
		"https://w3id.org/security/suites/ed25519-2020/v1",
	}
	doc.Subject = did.DID{Method: "example", SpecID: "123456789abcdefghi"}
	doc.VerificationMethods = []*did.VerificationMethod{
		{
			ID: did.URL{
				DID:         did.DID{Method: "example", SpecID: "123"},
				RawFragment: "#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
			},
			Type:       "JsonWebKey2020",
			Controller: did.DID{Method: "example", SpecID: "123"},
			Additional: map[string]json.RawMessage{
				"publicKeyJwk": json.RawMessage(`{
					"crv": "Ed25519",
					"x":   "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ",
					"kty": "OKP",
					"kid": "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"
				}`),
			},
		}, {
			ID: did.URL{
				DID:         did.DID{Method: "example", SpecID: "123456789abcdefghi"},
				RawFragment: "#keys-1",
			},
			Type:       "Ed25519VerificationKey2020",
			Controller: did.DID{Method: "example", SpecID: "pqrstuvwxyz0987654321"},
			Additional: map[string]json.RawMessage{
				"publicKeyMultibase": json.RawMessage(`"zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"`),
			},
		},
	}

	got, err := json.Marshal(doc)
	if err != nil {
		t.Fatal("DID document encoding error:", err)
	}

	if !bytes.Equal(want.Bytes(), got) {
		t.Errorf("got:  %s", got)
		t.Errorf("want: %s", want.Bytes())
	}
}

func TestServiceUnmarshalJSON(t *testing.T) {
	var doc did.Document
	err := json.Unmarshal([]byte(example20), &doc)
	if err != nil {
		t.Fatal(err)
	}

	if l := len(doc.Services); l != 1 {
		t.Fatalf("got %d services, want 1", l)
	}
	const wantID = "did:example:123#linked-domain"
	if got := doc.Services[0].ID.String(); got != wantID {
		t.Errorf("got service ID %q, want %q", got, wantID)
	}
	const wantType = "LinkedDomains"
	if got := doc.Services[0].Types; len(got) != 1 || got[0] != wantType {
		t.Errorf("got service type %q, want [%q]", got, wantType)
	}
	const wantEndpoint = "https://bar.example.com"
	if got := doc.Services[0].Endpoint.URIRefs; len(got) != 1 || got[0].String() != wantEndpoint {
		t.Errorf("got service endpoint strings %q, want [%q]", got, wantEndpoint)
	}
	if got := doc.Services[0].Endpoint.Maps; len(got) != 0 {
		t.Errorf("got service endpoint maps %q, want none", got)
	}
}

func TestServiceEndpointUnmarshalJSON(t *testing.T) {
	t.Run("InvalidURIString", func(t *testing.T) {
		const sample = `{"service": [{"id": "#ld0", "type": "LinkedDomains", "serviceEndpoint": ":"}]}`
		err := json.Unmarshal([]byte(sample), new(did.Document))
		if err == nil {
			t.Fatal("no error")
		}
		const want = "malformed DID service enpoint URI: missing protocol scheme"
		if got := err.Error(); got != want {
			t.Errorf("got error %q, want %q", got, want)
		}
	})

	t.Run("InvalidURIArray", func(t *testing.T) {
		const sample = `{"service": [{"id": "#ld0", "type": "LinkedDomains", "serviceEndpoint": ["http://127.0.0.1/", ":"]}]}`
		err := json.Unmarshal([]byte(sample), new(did.Document))
		if err == nil {
			t.Fatal("no error")
		}
		const want = "malformed DID service enpoint URI: missing protocol scheme"
		if got := err.Error(); got != want {
			t.Errorf("got error %q, want %q", got, want)
		}
	})
}
