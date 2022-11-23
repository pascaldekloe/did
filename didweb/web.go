// Package didweb provides standard HTTP connectivity.
package didweb

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/pascaldekloe/did"
)

// DownloadMaxDefault is an upper boundary for byte sizes.
// The default of 64 KiB provides good protection for most use-cases.
const DownloadMaxDefault = 1 << 16

// ErrDownloadMax signals an upper-boundary breach.
var ErrDownloadMax = errors.New("DID download abort on size constraints")

// Client uses HTTP to resolve documents.
// Multiple goroutines may invoke methods on a Client simultaneously.
type Client struct {
	http.Client
	// DownloadMax is the upper boundary for byte sizes. Zero defaults to
	// DownloadMaxDefault. Negative values disable the limit.
	DownloadMax int
}

// Resolve fetches a document in a standard compliant manner.
func (c *Client) Resolve(URL string) (*did.Document, *did.Meta, error) {
	req, err := http.NewRequest(http.MethodGet, URL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", did.ErrNotFound, err)
	}
	req.Header.Set("Accept", "application/did+json, application/did+ld+json;q=0.7, application/json;q=0.1")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("DID document lookup: %w", err)
	}
	switch res.StatusCode {
	case http.StatusOK:
		break
	case http.StatusNotFound:
		return nil, nil, did.ErrNotFound
	case http.StatusNotAcceptable:
		return nil, nil, fmt.Errorf("%w—want JSON", did.ErrMediaType)
	default:
		return nil, nil, fmt.Errorf("HTTP %q for DID document %s", res.Status, URL)
	}

	var m did.Meta
	if s := res.Header.Get("Last-Modified"); s != "" {
		// best-effort basis
		m.Updated, _ = http.ParseTime(s)
	}

	max := DownloadMaxDefault
	switch {
	case c.DownloadMax > 0:
		max = c.DownloadMax
	case c.DownloadMax < 0:
		// 1 GiB hard limit
		max = 1 << 30
	}
	r := io.LimitedReader{
		R: res.Body,
		N: int64(max),
	}

	var d did.Document
	err = json.NewDecoder(&r).Decode(&d)
	switch {
	case err == nil:
		return &d, &m, nil
	case r.N <= 0:
		return nil, nil, fmt.Errorf("%w: %s reached %d bytes", ErrDownloadMax, URL, max)
	default:
		return nil, nil, fmt.Errorf("DID document %q unavailable: %w", URL, err)
	}
}
