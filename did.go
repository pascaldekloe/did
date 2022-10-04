// Package did implements W3C's Decentralized Identifiers.
package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Attrs holds all attributes of a DID.
type Attrs struct {
	Method   string     // method name
	SpecID   string     // method-specific identifier
	Path     string     // optional
	Params   url.Values // optional
	Fragment string     // optional
}

// ErrScheme denies an input string.
var ErrScheme = errors.New("not a DID")

var errTerm = errors.New("DID incomplete")

// Parse interprets s in full, and it returns the mapping.
func Parse(s string) (*Attrs, error) {
	if !strings.HasPrefix(s, "did:") {
		return nil, ErrScheme
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("malformed DID URI: %w", err)
	}

	attrs := Attrs{
		Path:     u.Path,
		Fragment: u.Fragment,
	}

	methodEnd := strings.IndexByte(u.Opaque, ':')
	if methodEnd < 0 {
		return nil, errTerm
	}
	attrs.Method = u.Opaque[:methodEnd]
	attrs.SpecID = u.Opaque[methodEnd+1:]

	pathStart := strings.IndexByte(attrs.SpecID, '/')
	if pathStart >= 0 {
		attrs.Path = attrs.SpecID[pathStart:]
		attrs.SpecID = attrs.SpecID[:pathStart]
	}

	if u.RawQuery != "" {
		attrs.Params = u.Query()
	}

	return &attrs, nil
}

// URL returns a mapping to the standard Go domain.
func (attrs *Attrs) URL() *url.URL {
	return &url.URL{
		Scheme:   "did",
		Opaque:   attrs.Method + ":" + attrs.SpecID + attrs.Path,
		RawQuery: attrs.Params.Encode(),
		Fragment: attrs.Fragment,
	}
}

// String returns the DID URI.
func (attrs *Attrs) String() string {
	return attrs.URL().String()
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (attrs *Attrs) UnmarshalJSON(bytes []byte) error {
	var s string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}

	p, err := Parse(s)
	if err != nil {
		return fmt.Errorf("JSON string content: %w", err)
	}
	*attrs = *p // copy
	return nil
}
