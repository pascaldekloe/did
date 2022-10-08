package did_test

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/pascaldekloe/did"
)

var GoldenURLs = map[string]did.URL{
	"did:example:123456789abcdefghi": {
		DID: did.DID{
			Method: "example",
			SpecID: "123456789abcdefghi",
		},
	},
	"did:example:123456/path": {
		DID: did.DID{
			Method: "example",
			SpecID: "123456",
		},
		Path: "/path",
	},
	"did:example:123456?versionId=1": {
		DID: did.DID{
			Method: "example",
			SpecID: "123456",
		},
		Params: url.Values{"versionId": []string{"1"}},
	},
	"did:example:123#public-key-0": {
		DID: did.DID{
			Method: "example",
			SpecID: "123",
		},
		Fragment: "public-key-0",
	},
	"did:example:123#agent": {
		DID: did.DID{
			Method: "example",
			SpecID: "123",
		},
		Fragment: "agent",
	},
	"did:example:123?service=agent&relativeRef=/credentials#degree": {
		DID: did.DID{
			Method: "example",
			SpecID: "123",
		},
		Params: url.Values{
			"service":     []string{"agent"},
			"relativeRef": []string{"/credentials"},
		},
		Fragment: "degree",
	},
	"did:example:123?versionTime=2021-05-10T17:00:00Z": {
		DID: did.DID{
			Method: "example",
			SpecID: "123",
		},
		Params: url.Values{"versionTime": []string{"2021-05-10T17:00:00Z"}},
	},
	"did:example:123?service=files&relativeRef=/resume.pdf": {
		DID: did.DID{
			Method: "example",
			SpecID: "123",
		},
		Params: url.Values{"service": []string{"files"},
			"relativeRef": []string{"/resume.pdf"},
		},
	},
}

func TestParseURL(t *testing.T) {
	for s, want := range GoldenURLs {
		got, err := did.ParseURL(s)
		if err != nil {
			t.Errorf("DID %q got error: %s", s, err)
			continue
		}

		if got.Method != want.Method {
			t.Errorf("DID %q got method %q, want %q", s, got.Method, want.Method)
		}
		if got.SpecID != want.SpecID {
			t.Errorf("DID %q got method-specific identifier %q, want %q", s, got.SpecID, want.SpecID)
		}
		if got.Path != want.Path {
			t.Errorf("DID %q got path %q, want %q", s, got.Path, want.Path)
		}
		if !reflect.DeepEqual(got.Params, want.Params) {
			t.Errorf("DID %q got params %q, want %q", s, got.Params, want.Params)
		}
		if got.Fragment != want.Fragment {
			t.Errorf("DID %q got fragment %q, want %q", s, got.Fragment, want.Fragment)
		}
	}
}
