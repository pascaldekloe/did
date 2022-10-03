// Package did implements W3C's Decentralized Identifiers.
package did

import (
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
