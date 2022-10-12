package did

import (
	"errors"
	"time"
)

// Resolution Errors
var (
	// ErrInvalid matches the "invalidDid" error code.
	// “The DID supplied to the DID resolution function does not conform to
	// valid syntax.”
	ErrInvalid = errors.New("DID syntax not valid")

	// ErrNotFound matches the "notFound" error code.
	// “The DID resolver was unable to find the DID document resulting from
	// this resolution request.”
	ErrNotFound = errors.New("DID document not found")

	// ErrMediaType matches the "representationNotSupported" error code.
	// “This error code is returned if the representation requested via the
	// accept input metadata property is not supported by the DID method
	// and/or DID resolver implementation.”
	ErrMediaType = errors.New("DID document media type not supported")
)

// Resolve a DID into a Doc by using the “Read” operation of the DID.Method.
type Resolve func(DID) (*Doc, *Meta, error)

// Meta describes a Doc. Note that all properties are optional.
type Meta struct {
	Created       time.Time `json:"created,omitempty"`
	Updated       time.Time `json:"updated,omitempty"`
	Deactivated   time.Time `json:"deactivated,omitempty"`
	NextUpdate    time.Time `json:"nextUpdate,omitempty"`
	NextVersionID string    `json:"nextVersionId,omitempty"`
	EquivalentIDs []DID     `json:"equivalentId,omitempty"`
	CanonicalID   *DID      `json:"canonicalId,omitempty"`
}
