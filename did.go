// Package did implements W3C's Decentralized Identifiers.
package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const prefix = "did:"

// DID contains the variable attributes.
type DID struct {
	// Method names the applicable scheme of the DID. The token value must
	// consist of lower-case letters 'a'–'z' and/or decimals '0'–'9' only.
	Method string

	// Method-specific identifiers may result into escaped characters with
	// one or more percent-encodings.
	SpecID string
}

// ErrScheme denies an input string.
var ErrScheme = errors.New("not a DID")

var (
	errTerm = fmt.Errorf("%w: incomplete", ErrInvalid)
	errChar = fmt.Errorf("%w: illegal character", ErrInvalid)
	errPrct = fmt.Errorf("%w: broken percent-encoding", ErrInvalid)

	errURLPart = fmt.Errorf("%w: URL character '/', '?' or '#' found", ErrInvalid)
)

// Parse validates s in full, and it returns the mapping.
func Parse(s string) (DID, error) {
	var d DID
	if !strings.HasPrefix(s, prefix) {
		return d, ErrScheme
	}
	var err error
	d.Method, err = readMethodName(s[len(prefix):])
	if err != nil {
		return d, err
	}
	d.SpecID, err = parseSpecID(s[len(prefix)+len(d.Method)+1:])
	return d, err
}

// ReadMethodName returns s until separator ':'.
func readMethodName(s string) (string, error) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z':
			continue // valid

		case ':':
			// one or more characters required
			if i == 0 {
				return "", errTerm
			}
			return s[:i], nil

		default:
			return "", errChar
		}
	}
	// separator ':' not found
	return "", errTerm
}

func parseSpecID(s string) (string, error) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'.', '-', '_':
			continue // valid

		case '%':
			return unescape(s[:i], s[i:])

		case '/', '?', '#':
			return s[:i], errURLPart

		default:
			return "", errChar
		}
	}
	return s, nil
}

// Unescape returns the prefix as is, plus s with its percent encodings
// resolved.
func unescape(prefix, s string) (string, error) {
	var b strings.Builder
	// every 3-byte escape produces one byte
	b.Grow(len(prefix) + len(s))
	b.WriteString(prefix)

	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'.', '-', '_':
			b.WriteByte(s[i])

		case '%':
			if i+2 >= len(s) {
				return "", errTerm
			}
			n1 := hexNibble(s[i+1])
			n2 := hexNibble(s[i+2])
			i += 2
			if n1 > 15 || n2 > 15 {
				return "", errPrct
			}
			b.WriteByte(n1<<4 | n2)

		case '/', '?', '#':
			return b.String(), errURLPart

		default:
			return "", errChar
		}
	}
	return b.String(), nil
}

// HexNibble return the numeric value of a hexadecimal character.
func hexNibble(c byte) byte {
	switch c {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return c - '0'
	case 'A', 'B', 'C', 'D', 'E', 'F':
		return c - 'A' + 10
	default:
		return 16
	}
}

// Equal returns whether s compares equal to d. The method is compliant with the
// “Normalization and Comparison” rules as defined by RFC 3986, section 6.
func (d DID) Equal(s string) bool {
	// scheme compare
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	s = s[len(prefix):]

	// method compare
	if l := len(d.Method); l >= len(s) || s[l] != ':' || s[:l] != d.Method {
		return false
	}
	s = s[len(d.Method)+1:]

	// method-specific identifier compare includes percent-encoding
	for i := 0; i < len(d.SpecID); i++ {
		c := d.SpecID[i]

		if s == "" {
			return false
		}
		switch s[0] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z':
			if s[0] != c {
				return false
			}
			s = s[1:] // next byte

		case '%':
			if len(s) < 3 || hexvalOrZero(s[1], s[2]) != c {
				return false
			}
			s = s[3:] // next byte

		default:
			return false // invalid
		}
	}
	return s == ""
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
		RawPath:  p.Path,
		Params:   p.Query(),
		Fragment: p.Fragment,
	}
	if p.RawPath != "" {
		u.RawPath = p.RawPath
	}
	// BUG(pascaldekloe): Resolve does no apply percent encoding on RawPath yet.

	return u.String(), nil
}

var hexChars = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'}

// String returns the DID syntax.
func (d DID) String() string {
	i := 0
	for {
		if i >= len(d.SpecID) {
			return prefix + d.Method + ":" + d.SpecID
		}

		switch d.SpecID[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z':
			i++ // next
			continue
		}

		break
	}
	// needs percent-encoding

	var b strings.Builder
	// every byte-escape produces three bytes
	b.Grow(20 + len(d.Method) + len(d.SpecID))
	b.WriteString(prefix)
	b.WriteString(d.Method)
	b.WriteByte(':')
	b.WriteString(d.SpecID[:i])

	for s := d.SpecID; i < len(s); i++ {
		switch c := s[i]; c {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'.', '-', '_':
			b.WriteByte(c)

		default:
			b.WriteByte('%')
			b.WriteByte(hexChars[c>>4])
			b.WriteByte(hexChars[c&15])
		}
	}
	return b.String()
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
	RawPath  string     // optional
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

	u := URL{DID: d}

	// read path
	if s != "" && s[0] == '/' {
		pathEnd := strings.IndexAny(s, "?#")
		if pathEnd < 0 {
			u.RawPath = s
			return &u, nil
		}

		u.RawPath = s[:pathEnd]
		s = s[pathEnd:]
	}

	// read URL additions
	p, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("malformed DID selection: %w", err)
	}
	u.Fragment = p.Fragment
	if p.RawQuery != "" {
		u.Params = p.Query()
	}
	return &u, nil
}

// Equal returns whether s compares equal to u. The method is compliant with the
// “Normalization and Comparison” rules as defined by RFC 3986, section 6.
//
// Duplicate query-paramaters are compared in order of their respective
// appearance, i.e., "?foo=1&foo=2" is not equal to "?foo=2&foo=1".
func (u *URL) Equal(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '/', '?', '#':
			if !u.DID.Equal(s[:i]) {
				return false
			}

			p, err := url.Parse(s[i:])
			if err != nil {
				return false
			}
			return p.Fragment == u.Fragment && pathEqual(p.RawPath, u.RawPath) && u.queryEqual(p)
		}
	}

	return u.RawPath == "" && len(u.Params) == 0 && u.Fragment == "" && u.DID.Equal(s)
}

func pathEqual(s, t string) bool {
	// fast path
	if s == t {
		return true
	}

	// trim root
	if s == "" || t == "" {
		return false
	}
	if s[0] == '/' {
		s = s[1:]
	}
	if t[0] != '/' {
		t = t[1:]
	}

	for {
		switch {
		case s == "":
			return t == ""
		case t == "":
			return false

		case s[0] == t[0]:
			s = s[1:]
			t = t[1:]

		case s[0] == '/', t[0] == '/':
			return false

		case s[0] == '%' && len(s) > 2 && t[0] == hexvalOrZero(s[1], s[2]):
			s = s[3:]
			t = t[1:]
		case t[0] == '%' && len(t) > 2 && s[0] == hexvalOrZero(t[1], t[2]):
			s = s[1:]
			t = t[3:]

		default:
			return false
		}
	}
}

func hexvalOrZero(a, b byte) (v byte) {
	switch a {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		v = a - '0'
	case 'A', 'B', 'C', 'D', 'E', 'F':
		v = a - 'A' + 10
	default:
		return 0
	}
	v <<= 4

	switch b {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return v | (b - '0')
	case 'A', 'B', 'C', 'D', 'E', 'F':
		return v | (b - 'A' + 10)
	default:
		return 0
	}
}

func (u *URL) queryEqual(p *url.URL) bool {
	if p.RawQuery == "" {
		return len(u.Params) == 0
	}
	if len(u.Params) == 0 {
		return false
	}

	q := p.Query()
	if len(q) != len(u.Params) {
		return false
	}

	for name, values := range q {
		match := u.Params[name]
		if len(match) != len(values) {
			return false
		}
		for i := range match {
			if match[i] != values[i] {
				return false
			}
		}
	}
	return true
}

// GoURL returns a mapping to the Go model.
func (u *URL) GoURL() *url.URL {
	var pathSep string
	if u.RawPath != "" && u.RawPath[0] != '/' {
		pathSep = "/"
	}

	p := &url.URL{
		Scheme:   "did",
		Opaque:   u.Method + ":" + u.SpecID + pathSep + u.RawPath,
		Fragment: u.Fragment,
	}
	if len(u.Params) != 0 {
		p.RawQuery = u.Params.Encode()
	}
	return p
}

// String returns the DID URL.
func (u *URL) String() string {
	if u.RawPath == "" && len(u.Params) == 0 && u.Fragment == "" {
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
