// JSON-LD is omitted by design. According to the standard: “A remote context
// may also be referenced using a relative URL, which is resolved relative to
// the location of the document containing the reference.”. On top of that,
// “JSON documents can be interpreted as JSON-LD without having to be modified
// by referencing a context via an HTTP Link Header …”.
package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"
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

// VerificationMethod is a set of parameters that can be used together with a
// process to independently verify a proof. For example, a cryptographic public
// key can be used as a verification method with respect to a digital signature;
// in such usage, it verifies that the signer possessed the associated
// cryptographic private key.
type VerificationMethod struct {
	ID         URL    `json:"id"`         // required
	Type       string `json:"type"`       // required
	Controller DID    `json:"controller"` // required

	// A verification method MAY include additional properties.
	Additional map[string]json.RawMessage `json:",-"`
}

// AdditionalString returns the value if, and only if the property is present,
// and its value is a valid JSON string.
func (m *VerificationMethod) AdditionalString(property string) string {
	raw, ok := m.Additional[property]
	if !ok {
		return ""
	}
	var s string
	err := json.Unmarshal([]byte(raw), &s)
	if err != nil {
		return ""
	}
	return s
}

// MarshalJSON implements the json.Marshaler interface.
func (m *VerificationMethod) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 0, 256)

	buf = append(buf, `{"id":`...)
	buf = strconv.AppendQuote(buf, m.ID.String())

	buf = append(buf, `,"type":`...)
	buf = strconv.AppendQuote(buf, m.Type)

	buf = append(buf, `,"controller":`...)
	buf = strconv.AppendQuote(buf, m.Controller.String())

	for property, value := range m.Additional {
		switch property {
		case "id", "type", "controller":
			return nil, fmt.Errorf(`found core DID verification-method property %q in additional set`, property)
		}

		buf = append(buf, ',')
		buf = strconv.AppendQuote(buf, property)
		buf = append(buf, ':')
		buf = append(buf, value...)
	}

	buf = append(buf, '}')
	return buf, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (m *VerificationMethod) UnmarshalJSON(bytes []byte) error {
	// Read all properties as Additional first.
	err := json.Unmarshal(bytes, &m.Additional)
	if err != nil {
		return err
	}

	// Second, extract the core from Additional.
	err = m.popPropertyInto("id", &m.ID)
	if err != nil {
		return err
	}
	err = m.popPropertyInto("type", &m.Type)
	if err != nil {
		return err
	}
	return m.popPropertyInto("controller", &m.Controller)
}

// PopPropertyInto unmarshals a core property.
func (m *VerificationMethod) popPropertyInto(name string, pointer any) error {
	raw, ok := m.Additional[name]
	if !ok {
		return fmt.Errorf("DID verification-method JSON has no %q", name)
	}
	delete(m.Additional, name)

	err := json.Unmarshal([]byte(raw), pointer)
	if err != nil {
		return fmt.Errorf("DID verification-method JSON %q: %w", name, err)
	}
	return nil
}

// Services are used in DID documents to express ways of communicating with the
// DID subject or associated entities. A service can be any type of service the
// DID subject wants to advertise, including decentralized identity management
// services for further discovery, authentication, authorization, or
// interaction.
type Service struct {
	ID       url.URL         `json:"id"`
	Types    []string        `json:"type"` // one or more required
	Endpoint ServiceEndpoint `json:"serviceEndpoint"`

	// Each service extension MAY include additional properties and MAY
	// further restrict the properties associated with the extension.
	Additional map[string]json.RawMessage `json:",-"`
}

// AdditionalString returns the value if, and only if the property is present,
// and its value is a valid JSON string.
func (srv *Service) AdditionalString(property string) string {
	raw, ok := srv.Additional[property]
	if !ok {
		return ""
	}
	var s string
	err := json.Unmarshal([]byte(raw), &s)
	if err != nil {
		return ""
	}
	return s
}

var errNoServiceType = errors.New("no DID service type set")

// MarshalJSON implements the json.Marshaler interface.
func (srv *Service) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 0, 256)

	buf = append(buf, `{"id":`...)
	buf = strconv.AppendQuote(buf, srv.ID.String())

	buf = append(buf, `,"type":`...)
	switch len(srv.Types) {
	case 0:
		return nil, errNoServiceType
	case 1:
		buf = strconv.AppendQuote(buf, srv.Types[0])
	default:
		for i := range srv.Types {
			if i == 0 {
				buf = append(buf, '[')
			} else {
				buf = append(buf, ',')
			}
			buf = strconv.AppendQuote(buf, srv.Types[i])
		}
		buf = append(buf, ']')
	}

	buf = append(buf, `,"serviceEndpoint":`...)
	bytes, err := srv.Endpoint.MarshalJSON()
	if err != nil {
		return nil, err
	}
	buf = append(buf, bytes...)

	for property, value := range srv.Additional {
		switch property {
		case "id", "type", "serviceEndpoint":
			return nil, fmt.Errorf(`found core DID service property %q in additional set`, property)
		}

		buf = append(buf, ',')
		buf = strconv.AppendQuote(buf, property)
		buf = append(buf, ':')
		buf = append(buf, value...)
	}

	buf = append(buf, '}')
	return buf, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (srv *Service) UnmarshalJSON(bytes []byte) error {
	// Read all properties as Additional first.
	err := json.Unmarshal(bytes, &srv.Additional)
	if err != nil {
		return err
	}

	// Second, extract the core from Additional.
	if raw, ok := srv.Additional["id"]; !ok {
		return errors.New(`DID service JSON has no "id"`)
	} else {
		delete(srv.Additional, "id")
		var s string
		err := json.Unmarshal([]byte(raw), &s)
		if err != nil {
			return fmt.Errorf(`DID service JSON "id": %w`, err)
		}
		p, err := url.Parse(s)
		if err != nil {
			return fmt.Errorf(`DID service JSON "id" content: %w`, err)
		}
		srv.ID = *p
	}

	if raw, ok := srv.Additional["type"]; !ok {
		return errors.New(`DID service JSON has no "type"`)
	} else {
		delete(srv.Additional, "type")
		switch raw[0] {
		case '"':
			if cap(srv.Types) != 0 {
				srv.Types = srv.Types[:1]
			} else {
				srv.Types = make([]string, 1)
			}
			err := json.Unmarshal([]byte(raw), &srv.Types[0])
			if err != nil {
				return err
			}
		case '[':
			err := json.Unmarshal([]byte(raw), &srv.Types)
			if err != nil {
				return fmt.Errorf(`DID service JSON "type": %w`, err)
			}
		default:
			return fmt.Errorf(`DID service JSON "type" is not a string nor a set of strings: %.12q`, raw)
		}
	}

	if raw, ok := srv.Additional["serviceEndpoint"]; !ok {
		return errors.New(`DID service JSON has no "serviceEndpoint"`)
	} else {
		delete(srv.Additional, "serviceEndpoint")
		err := srv.Endpoint.UnmarshalJSON([]byte(raw))
		if err != nil {
			return err
		}
	}
	return nil
}

// ServiceEndpoint properties MUST be a string, a map, or a set composed of one
// or more strings and/or maps. All string values MUST be valid URIs conforming
// to RFC 3986 and normalized according to the Normalization and Comparison
// rules in RFC 3986 and to any normalization rules in its applicable URI scheme
// specification.
type ServiceEndpoint struct {
	URIRefs []string
	Objects []json.RawMessage
}

var errNoServiceEndpoint = errors.New("no DID service endpoint set")

// MarshalJSON implements the json.Marshaler interface.
func (e ServiceEndpoint) MarshalJSON() ([]byte, error) {
	switch {
	case len(e.URIRefs) == 0 && len(e.Objects) == 0:
		return nil, errNoServiceEndpoint
	case len(e.URIRefs) == 1 && len(e.Objects) == 0:
		return json.Marshal(e.URIRefs[0])
	case len(e.URIRefs) == 0 && len(e.Objects) == 1:
		return e.Objects[0], nil
	}

	bytes, err := json.Marshal(e.URIRefs)
	if err != nil {
		return nil, err
	}
	for _, raw := range e.Objects {
		bytes[len(bytes)-1] = ',' // flip array end
		bytes = append(bytes, raw...)
		bytes = append(bytes, ']') // new array end
	}
	return bytes, err
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (e *ServiceEndpoint) UnmarshalJSON(bytes []byte) error {
	// reset
	e.URIRefs = e.URIRefs[:0]
	e.Objects = e.Objects[:0]

	switch bytes[0] {
	case '"': // single string
		if cap(e.URIRefs) != 0 {
			e.URIRefs = e.URIRefs[:1]
		} else {
			e.URIRefs = make([]string, 1)
		}
		return json.Unmarshal(bytes, &e.URIRefs[0])

	case '{': // single map
		if cap(e.Objects) != 0 {
			e.Objects = e.Objects[:1]
		} else {
			e.Objects = make([]json.RawMessage, 1)
		}
		e.Objects[0] = make(json.RawMessage, len(bytes))
		copy(e.Objects[0], bytes)
		return nil

	case '[': // set composed of one or more strings and/or maps.
		break

	default:
		return fmt.Errorf("DID serviceEndpoint JSON is not a string nor a map nor a set: %.12q", bytes)
	}

	var set []json.RawMessage
	err := json.Unmarshal(bytes, &set)
	if err != nil {
		return err
	}
	if len(set) == 0 {
		return errors.New("DID serviceEndpoint JSON set empty")
	}
	for _, raw := range set {
		switch raw[0] {
		case '"':
			var s string
			err = json.Unmarshal([]byte(raw), &s)
			if err != nil {
				return err
			}
			e.URIRefs = append(e.URIRefs, s)
		case '{':
			e.Objects = append(e.Objects, raw)
		default:
			return fmt.Errorf("DID serviceEndpoint JSON set entry is not a string nor a map: %.12q", raw)
		}
	}
	return nil
}

// DID resolution errors standardise Resolve error cases conform W3C's
// recommendation.
var (
	// “The DID supplied to the DID resolution function does not conform to
	// valid syntax.”
	ErrInvalid = errors.New("invalid DID")

	// “The DID resolver was unable to find the DID document resulting from
	// this resolution request.”
	ErrNotFound = errors.New("DID document not found")

	// “This error code is returned if the representation requested via the
	// accept input metadata property is not supported by the DID method
	// and/or DID resolver implementation.”
	ErrMediaType = errors.New("DID document media type not supported")
)

// Resolve a DID into a Document by using the “Read” operation of the DID
// Method.
//
// Implementations should return ErrInvalid when encountering an "invalidDid"
// error code, or ErrNotFound on the "notFound" code, or ErrMediaType on the
// "representationNotSupported" code.
type Resolve func(DID) (*Document, *Meta, error)

// Meta describes a Document. Note that all properties are optional.
type Meta struct {
	Created       time.Time `json:"created,omitempty"`
	Updated       time.Time `json:"updated,omitempty"`
	Deactivated   time.Time `json:"deactivated,omitempty"`
	NextUpdate    time.Time `json:"nextUpdate,omitempty"`
	NextVersionID string    `json:"nextVersionId,omitempty"`
	EquivalentIDs []DID     `json:"equivalentId,omitempty"`
	CanonicalID   *DID      `json:"canonicalId,omitempty"`
}
