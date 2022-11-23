package did_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/pascaldekloe/did"
)

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

func TestVerificationMethodMarshalJSON(t *testing.T) {
	// BUG(pascaldekloe): Test has workaround for missing @context support.
	var example = "{" + example13[strings.Index(example13, `"id"`):]

	var want bytes.Buffer
	// normalize sample (in sync with json.Marshal output)
	err := json.Compact(&want, []byte(example))
	if err != nil {
		t.Fatal("sample preparation:", err)
	}

	doc := did.Document{Subject: did.DID{Method: "example", SpecID: "123456789abcdefghi"}}
	doc.VerificationMethods = []*did.VerificationMethod{
		{
			ID: did.URL{
				DID:      did.DID{Method: "example", SpecID: "123"},
				Fragment: "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
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
				DID:      did.DID{Method: "example", SpecID: "123456789abcdefghi"},
				Fragment: "keys-1",
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

func ExampleVerificationMethod_jSON() {
	var doc did.Document
	err := json.Unmarshal([]byte(example12), &doc)
	if err != nil {
		fmt.Println(err)
		return
	}

	if l := len(doc.VerificationMethods); l != 2 {
		fmt.Println("verifacition method count:", l)
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
