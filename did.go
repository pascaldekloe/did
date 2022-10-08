// Package did implements W3C's Decentralized Identifiers.
package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// DID contains the variable attributes.
type DID struct {
	Method string // name

	// Method-specific identifiers may contain percent-encodings.
	SpecID string
}

// ErrScheme denies an input string.
var ErrScheme = errors.New("not a DID")

var (
	errTerm = errors.New("incomplete DID")
	errChar = errors.New("illegal character in DID")
	errPrct = errors.New("broken percent-encoding in DID")

	errURLPart = errors.New("URL selection ('/', '?' or '#') in DID")
)

// Parse validates s in full, and it returns the mapping.
func Parse(s string) (DID, error) {
	const prefix = "did:"
	if !strings.HasPrefix(s, prefix) {
		return DID{}, ErrScheme
	}
	i := len(prefix)

ReadMethodName:
	for {
		if i >= len(s) {
			return DID{}, errTerm
		}
		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z':
			i++ // next

		case ':':
			break ReadMethodName // done

		default:
			return DID{}, errChar
		}
	}
	d := DID{Method: s[len(prefix):i]}
	i++

	// read method-specific ID
	if i >= len(s) {
		return d, errTerm
	}
	for i < len(s) {
		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'.', '-', '_':
			i++ // next

		case '%':
			for n := 0; n < 2; n++ {
				i++
				if i >= len(s) {
					return d, errTerm
				}
				switch s[i] {
				case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F':
					break // valid
				default:
					return d, errPrct
				}
			}
			i++ // next

		case '/', '?', '#':
			d.SpecID = s[len(prefix)+len(d.Method)+1 : i]
			return d, errURLPart

		default:
			return d, errChar
		}
	}

	d.SpecID = s[len(prefix)+len(d.Method)+1:]
	return d, nil
}

// Resolve returns an absolute URL, using the DID as a base URI.
func (base DID) Resolve(s string) (string, error) {
	p, err := url.Parse(s)
	if err != nil {
		return "", err
	}

	if p.IsAbs() {
		return s, nil
	}

	u := URL{
		DID:      base,
		Path:     p.Path,
		Params:   p.Query(),
		Fragment: p.Fragment,
	}
	return u.String(), nil
}

// String returns the DID without any validation on the attribute values.
func (d DID) String() string {
	return "did:" + d.Method + ":" + d.SpecID
}

// MarshalJSON implements the json.Marshaler interface.
func (d DID) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (d *DID) UnmarshalJSON(bytes []byte) error {
	var s string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}

	p, err := Parse(s)
	if err != nil {
		return fmt.Errorf("JSON string content: %w", err)
	}
	*d = p // copy
	return nil
}

// URL holds all attributes of a DID URL.
type URL struct {
	DID
	Path     string     // optional
	Params   url.Values // optional
	Fragment string     // optional
}

// ParseURL validates s in full, and it returns the mapping.
func ParseURL(s string) (*URL, error) {
	d, err := Parse(s)
	switch err {
	case nil:
		// no additions to DID
		return &URL{DID: d}, nil

	case errURLPart:
		// continue with additions
		s = s[5+len(d.Method)+len(d.SpecID):]

	default:
		return nil, err
	}

	// read URL additions
	p, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("malformed DID selection: %w", err)
	}

	u := URL{
		DID:      d,
		Path:     p.Path,
		Fragment: p.Fragment,
	}
	if p.RawQuery != "" {
		u.Params = p.Query()
	}
	return &u, nil
}

// GoURL returns a mapping to the Go model.
func (u *URL) GoURL() *url.URL {
	var pathSep string
	if len(u.Path) != 0 && u.Path[0] != '/' {
		pathSep = "/"
	}

	p := &url.URL{
		Scheme:   "did",
		Opaque:   u.Method + ":" + u.SpecID + pathSep + u.Path,
		Fragment: u.Fragment,
	}
	if len(u.Params) != 0 {
		p.RawQuery = u.Params.Encode()
	}
	return p
}

// String returns the DID URL.
func (u *URL) String() string {
	if u.Path == "" && len(u.Params) == 0 && u.Fragment == "" {
		return u.DID.String()
	}
	return u.GoURL().String()
}

// MarshalJSON implements the json.Marshaler interface.
func (u URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (u *URL) UnmarshalJSON(bytes []byte) error {
	var s string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}

	p, err := ParseURL(s)
	if err != nil {
		return fmt.Errorf("JSON string content: %w", err)
	}
	*u = *p // copy
	return nil
}
