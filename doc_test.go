package did_test

import (
	"encoding/json"
	"testing"

	"github.com/pascaldekloe/did"
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

// Example30 is borrowed from the W3C, excluding comments.
// https://www.w3.org/TR/did-core/#example-did-document-with-1-verification-method-type
const example30 = `{
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": "did:example:123",
    "authentication": [
      {
        "id": "did:example:123#z6MkecaLyHuYWkayBDLw5ihndj3T1m6zKTGqau3A51G7RBf3",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:example:123",
        "publicKeyMultibase": "zAKJP3f7BD6W4iWEQ9jwndVTCBq8ua2Utt8EEjJ6Vxsf"
      }
    ],
    "capabilityInvocation": [
      {
        "id": "did:example:123#z6MkhdmzFu659ZJ4XKj31vtEDmjvsi5yDZG5L7Caz63oP39k",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:example:123",
        "publicKeyMultibase": "z4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN"
      }
    ],
    "capabilityDelegation": [
      {
        "id": "did:example:123#z6Mkw94ByR26zMSkNdCUi6FNRsWnc2DFEeDXyBGJ5KTzSWyi",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:example:123",
        "publicKeyMultibase": "zHgo9PAmfeoxHG8Mn2XHXamxnnSwPpkyBHAMNF3VyXJCL"
      }
    ],
    "assertionMethod": [
      {
        "id": "did:example:123#z6MkiukuAuQAE8ozxvmahnQGzApvtW7KT5XXKfojjwbdEomY",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:example:123",
        "publicKeyMultibase": "z5TVraf9itbKXrRvt2DSS95Gw4vqU3CHAdetoufdcKazA"
      }
    ]
}`

// Example31 is borrowed from the W3C, excluding comments.
// https://www.w3.org/TR/did-core/#example-did-document-with-many-different-key-types
const example31 = `{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "verificationMethod": [
    {
      "id": "did:example:123#key-0",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"
      }
    },
    {
      "id": "did:example:123#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "X25519",
        "x": "pE_mG098rdQjY3MKK2D5SUQ6ZOEW3a6Z6T7Z4SgnzCE"
      }
    },
    {
      "id": "did:example:123#key-2",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "secp256k1",
        "x": "Z4Y3NNOxv0J6tCgqOBFnHnaZhJF6LdulT7z8A-2D5_8",
        "y": "i5a2NtJoUKXkLm6q8nOEu9WOkso1Ag6FTUT6k_LMnGk"
      }
    },
    {
      "id": "did:example:123#key-3",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "secp256k1",
        "x": "U1V4TVZVMUpUa0ZVU1NBcU9CRm5IbmFaaEpGNkxkdWx",
        "y": "i5a2NtJoUKXkLm6q8nOEu9WOkso1Ag6FTUT6k_LMnGk"
      }
    },
    {
      "id": "did:example:123#key-4",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "Ums5WVgwRkRTVVFnU3k5c2xvZllMbEcwM3NPRW91ZzN",
        "y": "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4"
      }
    },
    {
      "id": "did:example:123#key-5",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-384",
        "x": "VUZKSlUwMGdpSXplekRwODhzX2N4U1BYdHVYWUZsaXVDR25kZ1U0UXA4bDkxeHpE",
        "y": "jq4QoAHKiIzezDp88s_cxSPXtuXYFliuCGndgU4Qp8l91xzD1spCmFIzQgVjqvcP"
      }
    },
    {
      "id": "did:example:123#key-6",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-521",
        "x": "VTI5c1lYSmZWMmx1WkhNZ0dQTXhaYkhtSnBEU3UtSXZwdUtpZ0VOMnB6Z1d0U28tLVJ3ZC1uNzhuclduWnplRGMx",
        "y": "UW5WNVgwSnBkR052YVc0Z1VqY1B6LVpoZWNaRnliT3FMSUpqVk9sTEVUSDd1UGx5RzBnRW9NV25JWlhoUVZ5cFB5"
      }
    },
    {
      "id": "did:example:123#key-7",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "RSA",
        "e": "AQAB",
        "n": "UkhWaGJGOUZRMTlFVWtKSElBdENGV2hlU1F2djFNRXh1NVJMQ01UNGpWazlraEpLdjhKZU1YV2UzYldIYXRqUHNrZGYyZGxhR2tXNVFqdE9uVUtMNzQybXZyNHRDbGRLUzNVTElhVDFoSkluTUhIeGoyZ2N1Yk82ZUVlZ0FDUTRRU3U5TE8wSC1MTV9MM0RzUkFCQjdRamE4SGVjcHl1c3BXMVR1X0RicXhjU253ZW5kYW13TDUyVjE3ZUtobE80dVh3djJIRmx4dWZGSE0wS21DSnVqSUt5QXhqRF9tM3FfX0lpSFVWSEQxdERJRXZMUGhHOUF6c24zajk1ZC1zYU"
      }
    }
  ]
}`

func TestDocSubjectJSON(t *testing.T) {
	var doc did.Doc
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
	var doc did.Doc
	err := json.Unmarshal([]byte(example11), &doc)
	if err != nil {
		t.Fatal(err)
	}

	const want = "did:example:bcehfew7h32f32h7af3"
	if len(doc.Controllers) != 1 || !doc.Controllers.Contains(want) {
		t.Errorf("got controllers %q, want [%q]", doc.Controllers, want)
	}
}

func TestVerificationRelationshipUnmarshalJSON(t *testing.T) {
	var doc did.Doc
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

func TestEmbeddedVerificationMethods(t *testing.T) {
	var doc did.Doc
	err := json.Unmarshal([]byte(example31), &doc)
	if err != nil {
		t.Fatal(err)
	}

	e, err := doc.EmbeddedVerificationMethods()
	if err != nil {
		t.Fatal(err)
	}
	if l := len(e.PerID); l != 8 {
		for s := range e.PerID {
			t.Logf("got verification method %q", s)
		}
		t.Errorf("got %d verification methods, want 8", l)
	}
}

func TestEmbeddedVerificationMethods_relationships(t *testing.T) {
	var doc did.Doc
	err := json.Unmarshal([]byte(example30), &doc)
	if err != nil {
		t.Fatal(err)
	}

	e, err := doc.EmbeddedVerificationMethods()
	if err != nil {
		t.Fatal(err)
	}
	if l := len(e.PerID); l != 4 {
		for s := range e.PerID {
			t.Logf("got verification method %q", s)
		}
		t.Errorf("got %d verification methods, want 4", l)
	}
}
