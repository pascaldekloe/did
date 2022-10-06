package did

import (
	"encoding/json"
	"fmt"
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
