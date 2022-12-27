// Package did implements W3C's Decentralized Identifier (DID) standard.
// See https://www.w3.org/TR/did-core/ for the specification.
package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
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
	for i := range prefix {
		if i >= len(s) || s[i] != prefix[i] {
			return DID{}, &SyntaxError{S: s, I: i}
		}
	}
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
	if i >= len(s) {
		return "", i
	}

NoEscapes:
	for {
		if i >= len(s) {
			// must match: *( *idchar ":" ) 1*idchar
			if end := len(s) - 1; s[end] == ':' {
				return s[offset:end], end
			}
			return s[offset:], len(s)
		}

		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'.', '-', '_',
			':':
			// colon not allowed as last character check delayed
			i++

		case '%':
			break NoEscapes

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
			'.', '-', '_',
			':':
			// colon not allowed as last character check delayed
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

	specID = b.String()
	// must match: *( *idchar ":" ) 1*idchar
	if end := len(s) - 1; s[end] != ':' {
		return specID, len(s)
	}
	return specID[:len(specID)-1], len(s) - 1
}

// EqualString returns whether s conforms to the DID syntax, and whether it is
// equivalent to d according to the “Normalization and Comparison” rules of RFC
// 3986, section 6.
func (d DID) EqualString(s string) bool {
	// scheme compare
	if len(s) < len(prefix) || s[:len(prefix)] != prefix {
		return false
	}

	// method compare
	method, err := readMethodName(s)
	if err != nil || method != d.Method {
		return false
	}

	// method-specific identifier compare
	i := len(prefix) + len(method) + 1
	for j := 0; j < len(d.SpecID); j++ {
		c := d.SpecID[j]

		if i >= len(s) {
			return false
		}

		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'.', '-', '_':
			if s[i] != c {
				return false
			}
			i++

		case ':':
			// colon not allowed as last character
			if s[i] != c || j == len(d.SpecID)-1 {
				return false
			}
			i++

		case '%':
			v, err := parseHex(s, i+1)
			if err != nil || v != c {
				return false
			}
			i += 3

		default:
			return false // invalid
		}
	}
	return i >= len(s) // compared all
}

// String returns the DID syntax, with the empty string for the zero value. Any
// and all colon characters (':') in the method-specific identifier are escaped
// (with "%3A").
func (d DID) String() string {
	if d.Method == "" && d.SpecID == "" {
		return ""
	}

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

// URL extends the syntax of a basic DID to incorporate other standard URI
// components such as path, query, and fragment in order to locate a particular
// resource.
type URL struct {
	DID
	RawPath  string     // optional
	Query    url.Values // optional
	Fragment string     // optional
}

// ParseURL validates s in full. It returns the mapping if, and only if s
// conforms to the DID URL syntax specification. Errors will be of type
// *SyntaxError. ⚠️ Note that the URL can be IsRelative.
func ParseURL(s string) (*URL, error) {
	if s == "" {
		return nil, &SyntaxError{}
	}
	var u URL // result
	var i int // s index

	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		// has "did:" scheme
		method, err := readMethodName(s)
		if err != nil {
			return nil, err
		}
		u.Method = method

		u.SpecID, i = parseSpecID(s, len(prefix)+len(method)+1)
		if u.SpecID == "" {
			return nil, &SyntaxError{S: s, I: i}
		}
		if i >= len(s) {
			// no query and/or fragment
			return &u, nil
		}
		switch s[i] {
		case '/', '?', '#':
			break // URL additions
		default:
			return nil, &SyntaxError{S: s, I: i}
		}
	} else {
		// could be either another scheme or a relative URL
		for i, c := range s {
			// “A path segment that contains a colon character
			// (e.g., "this:that") cannot be used as the first
			// segment of a relative-path reference, as it would
			// be mistaken for a scheme name.”
			// — “URI: Generic Syntax” RFC 3986, subsection 4.2
			switch c {
			case ':':
				return nil, &SyntaxError{S: s, I: i, err: errors.New("no \"did:\" scheme")}
			default:
				continue

			case '/', '?', '#':
				// s is a relative URL
				break
			}
			break
		}
	}

	// Parse “Path” from “URI: Generic Syntax” RFC 3986, subsection 3.3.
	pathOffset := i
	for ; i < len(s); i++ {
		switch s[i] {
		// match path BNF excluding pct-encoded
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // unreserved
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', // unreserved
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // unreserved
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', // unreserved
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // unreserved
			'-', '.', '_', '~', // unreserved
			'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', // sub-delims
			':', '@', // pchar additions
			'/':
			continue

		// match pct-encoded BNF
		case '%':
			_, err := parseHex(s, i+1)
			if err != nil {
				return nil, err
			}
			i += 2

		// “The path is terminated by the first question mark ("?") or
		// number sign ("#") character, or by the end of the URI.”
		case '#', '?':
			u.RawPath = s[pathOffset:i]

			// https://github.com/pascaldekloe/did/issues/2
			p, err := url.Parse(s[i:])
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

		default:
			return nil, &SyntaxError{S: s, I: i}
		}
	}
	u.RawPath = s[pathOffset:]
	return &u, nil
}

// IsRelative returns whether u has a .DID component.
//
// “A relative DID URL is any URL value in a DID document that does not start
// with did:<method-name>:<method-specific-id>. More specifically, it is any URL
// value that does not start with the ABNF defined in 3.1 DID Syntax. The URL is
// expected to reference a resource in the same DID document.”
func (u *URL) IsRelative() bool { return u.Method == "" && u.SpecID == "" }

// Equal returns whether v is equivalent to u according to the “Normalization
// and Comparison” rules of RFC 3986, section 6. Path evaluation follows the
// logic of path.Clean. Duplicate query-parameters are compared in order of
// their appearance, i.e., "?foo=1&foo=2" is not equivalent to "?foo=2&foo=1".
//
// Relative URLs never compare equal. RFC 3986, subection 6.1, states “In
// testing for equivalence, applications should not directly compare relative
// references; the references should be converted to their respective target
// URIs before comparison.”.
func (u *URL) Equal(v *URL) bool {
	return v.Fragment == u.Fragment &&
		!v.IsRelative() && v.DID == u.DID &&
		pathEqual(v.RawPath, u.RawPath) &&
		queryEqual(v.Query, u.Query)
}

// EqualString returns whether s conforms to the DID URL syntax, and whether it
// is equivalent to u according to the “Normalization and Comparison” rules of
// RFC 3986, section 6. Path evaluation follows the logic of path.Clean.
// Duplicate query-parameters are compared in order of their appearance, i.e.,
// "?foo=1&foo=2" is not equivalent to "?foo=2&foo=1".
//
// Relative URLs never compare equal. RFC 3986, subection 6.1, states “In
// testing for equivalence, applications should not directly compare relative
// references; the references should be converted to their respective target
// URIs before comparison.”.
func (u *URL) EqualString(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '/', '?', '#':
			if !u.DID.EqualString(s[:i]) {
				return false
			}

			p, err := url.Parse(s[i:])
			if err != nil {
				return false
			}
			path := p.RawPath
			if path == "" {
				path = p.Path
			}
			return u.Fragment == p.Fragment && pathEqual(u.RawPath, path) && queryEqualURLQuery(u.Query, p)
		}
	}

	return u.RawPath == "" && len(u.Query) == 0 && u.Fragment == "" && u.DID.EqualString(s)
}

func pathEqual(a, b string) bool {
	if a == b {
		return true
	}
	if a == "" || b == "" {
		return false
	}

	// normalize without root
	a = path.Join("/", a)[1:]
	b = path.Join("/", b)[1:]

	for {
		switch {
		case a == "":
			return b == ""
		case b == "":
			return false
		}

		ac := a[0]
		if ac != '%' {
			a = a[1:]
		} else {
			var err error
			ac, err = parseHex(a, 1)
			if err != nil {
				return false
			}
			a = a[3:]
		}

		bc := b[0]
		if bc != '%' {
			b = b[1:]
		} else {
			var err error
			bc, err = parseHex(b, 1)
			if err != nil {
				return false
			}
			b = b[3:]
		}

		if ac != bc {
			return false
		}
	}
}

func queryEqualURLQuery(q url.Values, u *url.URL) bool {
	switch {
	case u.RawQuery == "":
		return len(q) == 0
	case len(q) == 0:
		return false
	default:
		return queryEqual(q, u.Query())
	}
}

func queryEqual(a, b url.Values) bool {
	if len(a) != len(b) {
		return false
	}

	for name, values := range a {
		match := b[name]

		if len(values) != len(match) {
			return false
		}
		for i := range values {
			if values[i] != match[i] {
				return false
			}
		}
	}
	return true
}

// GoURL returns a mapping to the Go model. Note that DID URLs go into .Opaque.
// In contrast, the IsRelative URLs use .Path instead, and without the .Scheme.
func (u *URL) GoURL() *url.URL {
	g := url.URL{Fragment: u.Fragment}

	if s := u.DID.String(); s == "" {
		g.RawPath = u.RawPath
		g.Path, _ = url.PathUnescape(u.RawPath)
	} else {
		g.Scheme = prefix[:len(prefix)-1]
		g.Opaque = s[len(prefix):]
		if u.RawPath != "" {
			if u.RawPath[0] != '/' {
				g.Opaque += "/"
			}
			g.Opaque += u.RawPath
		}
	}

	if len(u.Query) != 0 {
		g.RawQuery = u.Query.Encode()
	}
	return &g
}

// String returns the DID URL, with the empty string for the zero value. Any and
// all colon characters (':') in the method-specific identifier are escaped
// (with "%3A").
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

// SetVersionParams installs the standardised "versionId" and "versionTime". The
// zero value on either s or t omits the respective parameter.
func (u *URL) SetVersionParams(s string, t time.Time) {
	if s == "" {
		u.Query["versionId"] = append(u.Query["versionId"][:0], s)
	}

	if !t.IsZero() {
		// JSON production requires “normalized to UTC 00:00:00 and
		// without sub-second decimal precision”, as per subsection
		// 6.2.1 of the v1 specification.
		t := t.UTC()
		if t.Nanosecond() != 0 {
			t = t.Round(time.Second)
		}
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
