// JSON-LD is omitted by design. According to the standard: “A remote context
// may also be referenced using a relative URL, which is resolved relative to
// the location of the document containing the reference.”. On top of that,
// “JSON documents can be interpreted as JSON-LD without having to be modified
// by referencing a context via an HTTP Link Header …”.
package did

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// V1 is the (W3C) namespace URI.
const V1 = "https://www.w3.org/ns/did/v1"

// JSON is the (MIME) media type for JSON document production and consumption.
const JSON = "application/did+json"

// Document holds the “core properties” of a DID association [Subject].
type Document struct {
	Subject DID `json:"id"` // required

	AlsoKnownAs []string `json:"alsoKnownAs,omitempty"`
	Controllers Set      `json:"controller,omitempty"`

	// A DID document can express verification methods, such as
	// cryptographic public keys, which can be used to authenticate or
	// authorize interactions with the DID subject or associated parties.
	VerificationMethods []*VerificationMethod `json:"verificationMethod,omitempty"`

	// Authentication verification relationship is used to specify how the
	// Subject is expected to be authenticated.
	Authentication *VerificationRelationship `json:"authentication,omitempty"`

	// Assertion method verification relationship is used to specify how the
	// Subject is expected to express claims.
	AssertionMethod *VerificationRelationship `json:"assertionMethod,omitempty"`

	// Key agreement verification relationship is used to specify how an
	// entity can generate encryption material in order to transmit
	// confidential information intended for the Subject.
	KeyAgreement *VerificationRelationship `json:"keyAgreement,omitempty"`

	// Capability invocation verification relationship is used to specify a
	// verification method that might be used by the DID subject to invoke a
	// cryptographic capability.
	CapabilityInvocation *VerificationRelationship `json:"capabilityInvocation,omitempty"`

	// Capability delegation verification relationship is used to specify a
	// mechanism that might be used by the DID subject to delegate a
	// cryptographic capability to another party.
	CapabilityDelegation *VerificationRelationship `json:"capabilityDelegation,omitempty"`

	// Services are used to express ways of communicating with the Subject
	// or associated entities.
	Services []*Service `json:"service,omitempty"`
}

// VerificationMethod returns the VerificationMethods entry that matches URL s
// with its "id" property, with nil for not found.
func (doc *Document) VerificationMethodOrNil(s string) *VerificationMethod {
	// The URL must be valid. It can be relative.
	s, err := doc.Subject.ResolveReference(s)
	if err != nil {
		return nil
	}

	for _, m := range doc.VerificationMethods {
		if m.ID.Equal(s) {
			return m
		}
	}
	return nil
}

// Set represents a string, or a set of strings that confrom to the DID syntax.
type Set []DID

// Contains returns whether any of the set entries equal s.
func (set Set) Contains(s string) bool {
	for _, d := range set {
		if d.Equal(s) {
			return true
		}
	}
	return false
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (set *Set) UnmarshalJSON(bytes []byte) error {
	switch bytes[0] {
	case 'n': // null
		*set = nil
		return nil

	case '"':
		if cap(*set) != 0 {
			*set = (*set)[:1]
		} else {
			*set = make(Set, 1)
		}
		return (*set)[0].UnmarshalJSON(bytes)

	case '[':
		var strings []json.RawMessage
		err := json.Unmarshal(bytes, &strings)
		if err != nil {
			return err
		}

		if cap(*set) >= len(strings) {
			*set = (*set)[:len(strings)]
		} else {
			*set = make(Set, len(strings))
		}

		for i, s := range strings {
			err = (*set)[i].UnmarshalJSON([]byte(s))
			if err != nil {
				return err
			}
		}
		return nil

	default:
		return fmt.Errorf("DID string or a set of strings not a JSON string or array: %.12q", bytes)
	}
}

// VerificationRelationship expresses the relationship between the Document
// Subject and a VerificationMethod. Each verification method MAY be either
// embedded or referenced.
type VerificationRelationship struct {
	Methods []*VerificationMethod // embedded
	URIRefs []string              // referenced
}

// MarshalJSON implements the json.Marshaler interface.
func (r VerificationRelationship) MarshalJSON() ([]byte, error) {
	// embedded methods as JSON object array
	buf, err := json.Marshal(r.Methods)
	if err != nil {
		return nil, err
	}

	// URL refererences as JSON strings into array
	for _, s := range r.URIRefs {
		buf[len(buf)-1] = ',' // flip array end
		buf = strconv.AppendQuote(buf, s)
		buf = append(buf, ']') // new array end
	}

	return buf, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (r *VerificationRelationship) UnmarshalJSON(bytes []byte) error {
	// reset
	r.Methods = r.Methods[:0]
	r.URIRefs = r.URIRefs[:0]

	switch bytes[0] {
	case '[': // mixed array
		break

	case 'n': // null
		return nil

	default:
		return fmt.Errorf("DID set of verification methods is not a JSON array nor null: %.12q", bytes)
	}

	var elements []json.RawMessage
	err := json.Unmarshal(bytes, &elements)
	if err != nil {
		return err
	}

	for _, raw := range elements {
		switch raw[0] {
		case '{': // embedded
			m := new(VerificationMethod)
			err = m.UnmarshalJSON([]byte(raw))
			if err != nil {
				return err
			}
			r.Methods = append(r.Methods, m)

		case '"': // refererce
			var s string
			err = json.Unmarshal([]byte(raw), &s)
			if err != nil {
				return err
			}
			r.URIRefs = append(r.URIRefs, s)

		default:
			return fmt.Errorf("DID set of verification methods entry is not a JSON object nor a JSON string: %.12q", raw)
		}
	}

	return nil
}
