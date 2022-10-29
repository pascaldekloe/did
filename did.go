// Package did implements W3C's Decentralized Identifiers.
package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const prefix = "did:" // URI scheme selection

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

// SyntaxError denies a DID on validation.
type SyntaxError struct {
	// S is the original input as provided to the parser.
	S string

	// I has the index in S of the first illegal character [byte], with
	// len(S) for an unexpect end of S, or a negative value for undefined.
	I int

	// Err may specify an underlying cause, such as ErrScheme.
	Err error
}

// Error implements the standard error interface.
func (e *SyntaxError) Error() string {
	switch {
	case e.Err != nil:
		return "invalid DID: " + e.Err.Error()

	case e.I < 0:
		return "invalid DID"

	case e.I >= len(e.S):
		return "incomplete DID"

	case e.S[e.I] == '%':
		if len(e.S)-e.I < 3 {
			return "incomplete DID percent-encoding"
		}
		return fmt.Sprintf("illegal DID percent-encoding digits %q", e.S[e.I+1:e.I+3])

	default:
		return fmt.Sprintf("illegal character %q at DID byte № %d", e.S[e.I], e.I+1)
	}
}

// Unwrap implements the errors.Unwrap convention.
func (e SyntaxError) Unwrap() error {
	return e.Err
}

// Parse validates s in full, and it returns the mapping. If there is an error,
// it will be of type *SyntaxError.
func Parse(s string) (DID, error) {
	method, err := parseMethodName(s)
	if err != nil {
		return DID{}, err
	}
	specID, end := parseSpecID(s, len(prefix)+len(method)+1)
	if end < len(s) || specID == "" {
		return DID{}, &SyntaxError{S: s, I: end}
	}
	return DID{Method: method, SpecID: specID}, nil
}

func parseMethodName(s string) (string, error) {
	for i := range prefix {
		if i >= len(s) {
			return "", &SyntaxError{S: s, I: i}
		}
		if s[i] != prefix[i] {
			return "", &SyntaxError{S: s, I: i, Err: ErrScheme}
		}
	}

	for i := len(prefix); i < len(s); i++ {
		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z':
			continue // valid

		case ':':
			// one or more characters required
			if i == len(prefix) {
				return "", &SyntaxError{S: s, I: len(prefix)}
			}
			return s[len(prefix):i], nil

		default:
			// illegal character
			return "", &SyntaxError{S: s, I: i}
		}
	}
	// separator ':' not found
	return "", &SyntaxError{S: s, I: len(s)}
}

// ParseSpecID reads s[offset:], and returns the method-specific identifier fully escaped.
func parseSpecID(s string, offset int) (specID string, end int) {
	i := offset

NoEscapes:
	for {
		if i >= len(s) {
			// best-case scenario
			return s[offset:], len(s)
		}

		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'.', '-', '_':
			i++ // valid

		case '%':
			break NoEscapes

		case ':':
			// must match: *( *idchar ":" ) 1*idchar
			if i == len(s)-1 {
				return "", i
			}
			i++

		default:
			// illegal character
			return s[offset:i], i
		}
	}

	var b strings.Builder
	// every 3-byte escape produces 1 byte
	b.Grow(len(s) - offset)
	b.WriteString(s[offset:i])

	for i < len(s) {
		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'.', '-', '_':
			b.WriteByte(s[i])
			i++

		case ':':
			// must match: *( *idchar ":" ) 1*idchar
			if i == len(s)-1 {
				return "", i
			}
			b.WriteByte(s[i])
			i++

		case '%':
			if i+2 >= len(s) {
				return "", i
			}

			var v byte

			// decode first nibble
			switch c := s[i+1]; c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				v = c - '0'
			case 'A', 'B', 'C', 'D', 'E', 'F':
				v = c - 'A' + 10
			default:
				// illegal character
				return "", i
			}

			v <<= 4

			// decode second nibble
			switch c := s[i+2]; c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				v |= c - '0'
			case 'A', 'B', 'C', 'D', 'E', 'F':
				v |= c - 'A' + 10
			default:
				// illegal character
				return "", i
			}

			b.WriteByte(v)
			i += 3

		default:
			// illegal character
			return b.String(), i
		}
	}

	return b.String(), len(s)
}

// Equal returns whether s compares equal to d. The method is compliant with the
// “Normalization and Comparison” rules as defined by RFC 3986, section 6.
func (d DID) Equal(s string) bool {
	// scheme compare
	if len(s) < len(prefix) || s[:len(prefix)] != prefix {
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
		Query:    p.Query(),
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
	Query    url.Values // optional
	Fragment string     // optional
}

// ParseURL validates s in full, and it returns the mapping. If there is an
// error, it will be of type *SyntaxError.
func ParseURL(s string) (*URL, error) {
	method, err := parseMethodName(s)
	if err != nil {
		return nil, err
	}

	specID, end := parseSpecID(s, len(prefix)+len(method)+1)
	u := URL{DID: DID{Method: method, SpecID: specID}}
	if end >= len(s) {
		if specID == "" {
			return nil, &SyntaxError{S: s, I: len(s)}
		}

		// no query and/or fragment
		return &u, nil
	}

	switch s[end] {
	default:
		return nil, &SyntaxError{S: s, I: end}

	case '#', '?':
		break // good

	case '/':
		offset := end
	PathRead:
		for {
			end++
			if end >= len(s) {
				u.RawPath = s[offset:]
				return &u, nil
			}
			// BUG(pascaldekloe): ParseURL does not validate the path.
			switch s[end] {
			case '#', '?':
				u.RawPath = s[offset:end]
				break PathRead
			}
		}
	}
	// got URL fragment and/or query in s[end:]

	p, err := url.Parse(s[end:])
	if err != nil {
		return nil, &SyntaxError{S: s, Err: err}
	}
	u.Fragment = p.Fragment
	if p.RawQuery != "" {
		u.Query = p.Query()
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
			return u.Fragment == p.Fragment && pathEqual(u.RawPath, p) && u.queryEqual(p)
		}
	}

	return u.RawPath == "" && len(u.Query) == 0 && u.Fragment == "" && u.DID.Equal(s)
}

func pathEqual(s string, u *url.URL) bool {
	t := u.RawPath
	if t == "" {
		t = u.Path
	}

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
	if t[0] == '/' {
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
		return len(u.Query) == 0
	}
	if len(u.Query) == 0 {
		return false
	}

	q := p.Query()
	if len(q) != len(u.Query) {
		return false
	}

	for name, values := range q {
		match := u.Query[name]
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
	if len(u.Query) != 0 {
		p.RawQuery = u.Query.Encode()
	}
	return p
}

// String returns the DID URL.
func (u *URL) String() string {
	if u.RawPath == "" && len(u.Query) == 0 && u.Fragment == "" {
		return u.DID.String()
	}
	return u.GoURL().String()
}

var (
	errVersionIDDupe   = errors.New("duplicate versionId in DID URL")
	errVersionTimeDupe = errors.New("duplicate versionTime in DID URL")
)

// VersionParams returns the standardised "versionId" and "versionTime".
func (u *URL) VersionParams() (string, time.Time, error) {
	var s string
	switch a := u.Query["versionId"]; len(a) {
	case 0:
		break
	case 1:
		s = a[0]
	default:
		return "", time.Time{}, errVersionIDDupe
	}

	switch a := u.Query["versionTime"]; len(a) {
	case 0:
		return s, time.Time{}, nil
	case 1:
		t, err := time.Parse(time.RFC3339, a[0])
		if err != nil {
			return "", time.Time{}, fmt.Errorf("versionTime in DID URL: %w", err)
		}
		return s, t, nil
	default:
		return "", time.Time{}, errVersionTimeDupe
	}
}

// SetVersionParams installs the standardised "versionId" and "versionTime".
func (u *URL) SetVersionParams(s string, t time.Time) {
	if s == "" {
		u.Query["versionId"] = append(u.Query["versionId"][:0], s)
	}

	if !t.IsZero() {
		u.Query["versionTime"] = append(u.Query["versionTime"][:0], t.Format(time.RFC3339))
	}
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
