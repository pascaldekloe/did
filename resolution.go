package did

import (
	"errors"
	"time"
)

// DID resolution errors standardise Resolve error cases conform W3C's
// recommendation.
var (
	// “The DID supplied to the DID resolution function does not conform to
	// valid syntax.”
	ErrInvalid = errors.New("invalid DID")

	// “The DID resolver was unable to find the DID document resulting from
	// this resolution request.”
	ErrNotFound = errors.New("DID document not found")

	// “This error code is returned if the representation requested via the
	// accept input metadata property is not supported by the DID method
	// and/or DID resolver implementation.”
	ErrMediaType = errors.New("DID document media type not supported")
)

// Resolve a DID into a Document by using the “Read” operation of the DID
// Method.
//
// Implementations should return ErrInvalid when encountering an "invalidDid"
// error code, or ErrNotFound on the "notFound" code, or ErrMediaType on the
// "representationNotSupported" code.
type Resolve func(DID) (*Document, *Meta, error)

// Meta describes a Document. Note that all properties are optional.
type Meta struct {
	Created       time.Time `json:"created,omitempty"`
	Updated       time.Time `json:"updated,omitempty"`
	Deactivated   time.Time `json:"deactivated,omitempty"`
	NextUpdate    time.Time `json:"nextUpdate,omitempty"`
	NextVersionID string    `json:"nextVersionId,omitempty"`
	EquivalentIDs []DID     `json:"equivalentId,omitempty"`
	CanonicalID   *DID      `json:"canonicalId,omitempty"`
}
