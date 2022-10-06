package did_test

import (
	"encoding/json"
	"fmt"

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

func ExampleVerificationMethod_jSON() {
	var doc did.Doc
	err := json.Unmarshal([]byte(example12), &doc)
	if err != nil {
		fmt.Println(err)
		return
	}

	method0 := doc.VerificationMethods[0]
	bytes := method0.Additional["publicKeyJwk"]
	fmt.Printf("• %s has JWK %s\n", &method0.ID, bytes)

	method1 := doc.VerificationMethods[1]
	s, err := method1.AdditionalString("publicKeyMultibase")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("• %s has multibase %s\n", &method1.ID, s)
	// Output:
	// • did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A has JWK {
	//       "crv": "Ed25519",
	//       "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ",
	//       "kty": "OKP",
	//       "kid": "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"
	//     }
	// • did:example:123456789abcdefghi#keys-1 has multibase zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV
}
