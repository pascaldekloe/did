package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

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
	Additional map[string]json.RawMessage `json:",embed"`
}

// AdditionalString returns the value, if the property is present, and the value
// is a JSON string. The return is zero on property absence.
func (method *VerificationMethod) AdditionalString(property string) (value string, _ error) {
	raw, ok := method.Additional[property]
	if ok {
		return value, json.Unmarshal([]byte(raw), &value)
	}
	return "", nil
}

// MarshalJSON implements the json.Marshaler interface.
func (method *VerificationMethod) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 0, 256)

	buf = append(buf, `{"id":`...)
	buf = strconv.AppendQuote(buf, method.ID.String())

	buf = append(buf, `,"type":`...)
	buf = strconv.AppendQuote(buf, method.Type)

	buf = append(buf, `,"controller":`...)
	buf = strconv.AppendQuote(buf, method.Controller.String())

	for property, value := range method.Additional {
		switch property {
		case "id", "type", "controller":
			return nil, fmt.Errorf(`found required DID verification-method property %q in additional set`, property)
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
func (method *VerificationMethod) UnmarshalJSON(bytes []byte) error {
	// Read all properties as Additional first.
	err := json.Unmarshal(bytes, &method.Additional)
	if err != nil {
		return err
	}

	// Second, extract the required from Additional.
	err = method.popPropertyInto("id", &method.ID)
	if err != nil {
		return err
	}
	err = method.popPropertyInto("type", &method.Type)
	if err != nil {
		return err
	}
	return method.popPropertyInto("controller", &method.Controller)
}

// PopPropertyInto unmarshals a required property.
func (method *VerificationMethod) popPropertyInto(name string, pointer any) error {
	raw, ok := method.Additional[name]
	if !ok {
		return fmt.Errorf(`missing DID verification-method property %q`, name)
	}
	delete(method.Additional, name)

	err := json.Unmarshal([]byte(raw), pointer)
	if err != nil {
		return fmt.Errorf(`broken DID verification-method property %q: %w`, name, err)
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
	Types    []string        `json:"type"`
	Endpoint ServiceEndpoint `json:"serviceEndpoint"`

	// Each service extension MAY include additional properties and MAY
	// further restrict the properties associated with the extension.
	Additional map[string]json.RawMessage `json:",embed"`
}

// AdditionalString returns the value, if the property is present, and the value
// is a JSON string. The return is zero on property absence.
func (service *Service) AdditionalString(property string) (value string, _ error) {
	raw, ok := service.Additional[property]
	if ok {
		return value, json.Unmarshal([]byte(raw), &value)
	}
	return "", nil
}

// MarshalJSON implements the json.Marshaler interface.
func (srv *Service) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 0, 256)

	buf = append(buf, `{"id":`...)
	buf = strconv.AppendQuote(buf, srv.ID.String())

	buf = append(buf, `,"type":`...)
	switch len(srv.Types) {
	case 0:
		return nil, errors.New(`required DID service property "type" has on value`)
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
			return nil, fmt.Errorf(`found required DID service property %q in additional set`, property)
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

	// Second, extract the required from Additional.
	err = srv.popPropertyInto("id", &srv.ID)
	if err != nil {
		return err
	}
	// BUG(pascaldekloe): Can't unmarshal single strings for service type.
	err = srv.popPropertyInto("type", &srv.Types)
	if err != nil {
		return err
	}
	return srv.popPropertyInto("serviceEndpoint", &srv.Endpoint)
}

// PopPropertyInto unmarshals a required property.
func (srv *Service) popPropertyInto(name string, pointer any) error {
	raw, ok := srv.Additional[name]
	if !ok {
		return fmt.Errorf(`missing DID service property %q`, name)
	}
	delete(srv.Additional, name)

	err := json.Unmarshal([]byte(raw), pointer)
	if err != nil {
		return fmt.Errorf(`broken DID service property %q: %w`, name, err)
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

// MarshalJSON implements the json.Marshaler interface.
func (e *ServiceEndpoint) MarshalJSON() ([]byte, error) {
	switch {
	case len(e.URIRefs) == 0 && len(e.Objects) == 0:
		return []byte{'[', ']'}, nil
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