package did

import (
	"encoding/json"
	"fmt"
)

// Doc holds the “core properties” of a DID document.
type Doc struct {
	Subject             DID                   `json:"id"`
	Controllers         Set                   `json:"controller,omitempty"`
	VerificationMethods []*VerificationMethod `json:"verificationMethod,omitempty"`
}

// Set represents a string, or a set of strings that confrom to the DID syntax.
type Set []DID

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
