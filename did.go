// Package did implements W3C's Decentralized Identifier (DID) standard.
// See https://www.w3.org/TR/did-core/ for the specification.
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
	// Method names the applicable scheme of the DID. The token value MUST
	// consist of lower-case letters 'a'–'z' and/or decimals '0'–'9' only.
	//
	// Use constants when setting this property to prevent malformed DID
	// production (with String). Instances returned by the parse methods
	// always contain a valid method.
	Method string

	// Method-specific identifiers may or may not contain a valid UTF-8
	// sequence. The W3C standard puts no constaints on the (byte) content.
	SpecID string
}

// SyntaxError denies a DID string on validation constraints.
type SyntaxError struct {
	// S is the original input as provided to the parser.
	S string

	// I has the index of the first illegal character [byte] in S, with
	// len(S) for an unexpected end of input, or -1 for location unknown.
	I int

	err error // optional cause
}

// Error implements the standard error interface.
func (e *SyntaxError) Error() string {
	var desc string
	switch {
	case e.err != nil:
		desc = e.err.Error()
	case e.I < 0:
		desc = "reason unknown" // should not happen ™️
	case e.I < len(prefix):
		desc = `no "` + prefix + `" scheme`
	case e.I >= len(e.S):
		desc = "end incomplete"
	default:
		desc = fmt.Sprintf("illegal %q at byte № %d", e.S[e.I], e.I+1)
	}

	if len(e.S) <= 200 {
		return fmt.Sprintf("invalid DID %q: %s", e.S, desc)
	}
	return fmt.Sprintf("invalid DID %q [truncated]: %s", e.S[:199]+"…", desc)
}

// Unwrap implements the errors.Unwrap convention.
func (e *SyntaxError) Unwrap() error {
	return e.err
}

// Parse validates s in full. It returns the mapping if, and only if s conforms
// to the DID syntax specification. Errors will be of type *SyntaxError.
func Parse(s string) (DID, error) {
	method, err := readMethodName(s)
	if err != nil {
		return DID{}, err
	}
	specID, end := parseSpecID(s, len(prefix)+len(method)+1)
	if end < len(s) || specID == "" {
		return DID{}, &SyntaxError{S: s, I: end}
	}
	return DID{Method: method, SpecID: specID}, nil
}

func readMethodName(s string) (string, error) {
	for i := range prefix {
		if i >= len(s) || s[i] != prefix[i] {
			return "", &SyntaxError{S: s, I: i}
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
			v, err := parseHex(s, i+1)
			if err != nil {
				return "", err.(*SyntaxError).I
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
	s = s[len(prefix):] // pass

	// method compare
	if l := len(d.Method); l >= len(s) || s[l] != ':' || s[:l] != d.Method {
		return false
	}
	s = s[len(d.Method)+1:] // pass

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
			s = s[1:] // pass

		case '%':
			v, err := parseHex(s, 1)
			if err != nil || v != c {
				return false
			}
			s = s[3:] // pass

		default:
			return false // invalid
		}
	}
	return s == ""
}

// ResolveReference resolves URI reference r to an absolute URI from base URI d,
// conform RFC 3986, section 5: “Reference Resolution”. The URI reference may be
// absolute or relative. If r is an absolute URL, then ResolveReference ignores
// d and it returns r as is.
func (d DID) ResolveReference(r string) (string, error) {
	p, err := url.Parse(r)
	if err != nil {
		return "", err
	}

	if p.IsAbs() {
		return r, nil
	}

	u := URL{
		DID:      d, // copy
		RawPath:  p.Path,
		Query:    p.Query(),
		Fragment: p.Fragment,
	}
	if p.RawPath != "" {
		u.RawPath = p.RawPath
	}

	return u.String(), nil
}

// String returns the DID syntax.
func (d DID) String() string {
	var escapeN int
	for i := 0; i < len(d.SpecID); i++ {
		switch d.SpecID[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'.', '-', '_':
			continue // valid
		default:
			escapeN++
		}
	}

	if escapeN == 0 {
		return prefix + d.Method + ":" + d.SpecID
	}

	var b strings.Builder
	b.Grow(len(prefix) + len(d.Method) + 1 + len(d.SpecID) + 2*escapeN)
	b.WriteString(prefix)
	b.WriteString(d.Method)
	b.WriteByte(':')

	for i := 0; i < len(d.SpecID); i++ {
		switch c := d.SpecID[i]; c {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'.', '-', '_':
			b.WriteByte(c)

		default:
			b.WriteByte('%')
			b.WriteByte(hexTable[c>>4])
			b.WriteByte(hexTable[c&15])
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

// ParseURL validates s in full. It returns the mapping if, and only if s
// conforms to the DID URL syntax specification. Errors will be of type
// *SyntaxError.
func ParseURL(s string) (*URL, error) {
	method, err := readMethodName(s)
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
		u.RawPath, err = readPath(s, offset)
		if err != nil {
			return nil, err
		}
		end += len(u.RawPath)
		if end >= len(s) {
			return &u, nil
		}
	}
	// got URL fragment and/or query in s[end:]

	p, err := url.Parse(s[end:])
	if err != nil {
		var wrap *url.Error // not usefull
		if errors.As(err, &wrap) {
			err = wrap.Err // trim
		}
		return nil, &SyntaxError{S: s, I: -1, err: err}
	}
	u.Fragment = p.Fragment
	if p.RawQuery != "" {
		u.Query = p.Query()
	}
	return &u, nil
}

func readPath(s string, offset int) (string, error) {
	for i := offset; i < len(s); i++ {
		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'-', '.', '_', '~', // unreserved
			'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', // sub-delims
			':', '@': // path specific
			continue // valid

		case '#', '?':
			// “The path is terminated by the first question mark
			// ("?") or number sign ("#") character, or by the end
			// of the URI.”
			// — “URI: Generic Syntax” RFC 3986, subsection 3.3
			return s[offset:i], nil

		case '%':
			_, err := parseHex(s, i+1)
			if err != nil {
				return "", err
			}
			i += 2
		}
	}

	return s[offset:], nil
}

// Equal returns whether s compares equal to u. The method is compliant with the
// “Normalization and Comparison” rules as defined by RFC 3986, section 6.
//
// Duplicate query-parameters are compared in order of their respective
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
		}

		sc := s[0]
		if sc != '%' {
			s = s[1:]
		} else {
			var err error
			sc, err = parseHex(s, 1)
			if err != nil {
				return false
			}
			s = s[3:]
		}

		tc := t[0]
		if tc != '%' {
			t = t[1:]
		} else {
			var err error
			tc, err = parseHex(t, 1)
			if err != nil {
				return false
			}
			t = t[3:]
		}

		if sc != tc {
			return false
		}
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

// PathWithEscape returns the RawPath with any and all of its percent-encodings
// resolved. Malformed and/or incomplete percent-encodings are returned as is.
//
// Encoded path-separators ("%2F") are replaced by the escape character followed
// by the path-separator character ('/'). Escape-character occurrences are
// replaced by two sequential escape characters. Percent-encodings that resolve
// to the escape character get replaced by two sequential escape characters.
func (u *URL) PathWithEscape(escape byte) string {
	s := u.RawPath
	i := 0
	for {
		if i >= len(s) {
			return s // fast path
		}

		if s[i] == escape || s[i] == '%' {
			break
		}

		i++
	}

	var b strings.Builder
	b.WriteString(s[:i])

	for i < len(s) {
		switch s[i] {
		default:
			b.WriteByte(s[i])
			i++
		case escape:
			b.WriteByte(escape)
			b.WriteByte(escape)
			i++
		case '%':
			if i+2 >= len(s) {
				// incomplete percent-encoding
				b.WriteByte(s[i])
				i++
				continue
			}

			var v byte

			// decode first nibble
			switch c := s[i+1]; c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				v = (c - '0') << 4
			case 'A', 'B', 'C', 'D', 'E', 'F':
				v = (c - 'A' + 10) << 4
			default:
				// illegal character
				b.WriteByte(s[i])
				i++
				continue
			}

			// decode second nibble
			switch c := s[i+2]; c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				v |= c - '0'
			case 'A', 'B', 'C', 'D', 'E', 'F':
				v |= c - 'A' + 10
			default:
				// illegal character
				b.WriteByte(s[i])
				i++
				b.WriteByte(s[i])
				i++
				continue
			}

			switch v {
			default:
				b.WriteByte(v)
			case escape:
				b.WriteByte(escape)
				b.WriteByte(escape)
			case '/':
				b.WriteByte(escape)
				b.WriteByte('/')
			}

			i += 3
		}
	}

	return b.String()
}

// PathSegments returns each component from the path in a foolproof manner.
// Percent-encodings get resolved on best-effort basis. Malformed encodings
// simply pass as is. The return is guaranteed to be equal to any and all
// arguments passed to SetPathSegments.
func (u *URL) PathSegments() []string {
	if u.RawPath == "" {
		return nil
	}

	s := strings.TrimPrefix(u.RawPath, "/")
	segs := make([]string, 0, strings.Count(s, "/"))

	// apply each directory
	for {
		i := strings.IndexByte(s, '/')
		if i < 0 {
			break
		}
		segs = append(segs, pathUnescape(s[:i]))
		s = s[i+1:]
	}

	// apply the last segment
	if s != "" {
		segs = append(segs, pathUnescape(s))
	}

	return segs
}

// PathUnescape resolves percent-encoding on best-effort basis.
// Malformend encodings are passed as is.
func pathUnescape(s string) string {
	i := strings.IndexByte(s, '%')
	if i < 0 {
		return s // fast path
	}

	var b strings.Builder
	for ; i >= 0; i = strings.IndexByte(s, '%') {
		v, err := parseHex(s, i+1)
		if err != nil {
			b.WriteString(s[:i+1]) // all including the '%'
			s = s[i+1:]            // pass '%'
			continue
		}

		b.WriteString(s[:i]) // all before the '%'
		b.WriteByte(v)       // escaped value
		s = s[i+3:]          // pass '%' and both hex digits
	}
	b.WriteString(s)
	return b.String()
}

// SetPathSegments updates the path in a foolproof manner. Unsafe characters are
// replaced by their percent-encodings. The return of PathSegments is guaranteed
// to be equal to any and all arguments passed to SetPathSegments.
func (u *URL) SetPathSegments(segs ...string) {
	if len(segs) == 0 {
		u.RawPath = ""
		return
	}

	var b strings.Builder
	for _, s := range segs {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(s))
	}
	if segs[len(segs)-1] == "" {
		b.WriteByte('/')
	}
	u.RawPath = b.String()
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
func (u *URL) MarshalJSON() ([]byte, error) {
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

// HexTable maps a nibble to its encoded value.
//
// “For consistency, URI producers and normalizers should use uppercase
// hexadecimal digits for all percent-encodings.”
// — “URI: Generic Syntax” RFC 3986, subsection 2.1
var hexTable = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'}

// ParseHex returns the interpretation of two hex digits, starting at index i.
func parseHex(s string, i int) (byte, error) {
	var v byte

	if i >= len(s) {
		return 0, &SyntaxError{S: s, I: i}
	}
	switch c := s[i]; c {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		v = c - '0'
	case 'A', 'B', 'C', 'D', 'E', 'F':
		v = c - 'A' + 10
	case 'a', 'b', 'c', 'd', 'e', 'f':
		v = c - 'a' + 10
	default:
		return 0, &SyntaxError{S: s, I: i}
	}
	v <<= 4

	i++
	if i >= len(s) {
		return 0, &SyntaxError{S: s, I: i}
	}
	switch c := s[i]; c {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		v |= c - '0'
	case 'A', 'B', 'C', 'D', 'E', 'F':
		v |= c - 'A' + 10
	case 'a', 'b', 'c', 'd', 'e', 'f':
		v |= c - 'a' + 10
	default:
		return 0, &SyntaxError{S: s, I: i}
	}
	return v, nil
}
