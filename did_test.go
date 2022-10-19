package did_test

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"
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
		RawPath: "/path",
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
		if got.RawPath != want.RawPath {
			t.Errorf("DID %q got raw path %q, want %q", s, got.RawPath, want.RawPath)
		}
		if !reflect.DeepEqual(got.Params, want.Params) {
			t.Errorf("DID %q got params %q, want %q", s, got.Params, want.Params)
		}
		if got.Fragment != want.Fragment {
			t.Errorf("DID %q got fragment %q, want %q", s, got.Fragment, want.Fragment)
		}
	}
}

func ExampleParse_percentEncoding() {
	d, err := did.Parse("did:example:escaped%F0%9F%A4%96")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("parsed: " + d.SpecID)
	fmt.Println("string: " + d.String())
	// Output:
	// parsed: escaped🤖
	// string: did:example:escaped%F0%9F%A4%96
}

func TestDIDEqual(t *testing.T) {
	// TODO(pascaldekloe): needs better test set
	for s, u := range GoldenURLs {
		// trim URL parts, if any
		if i := strings.IndexAny(s, "/?#"); i >= 0 {
			s = s[:i]
		}

		if !u.DID.Equal(s) {
			t.Errorf("%#v.Equal(%q) got false, want true", u.DID, s)
		}
	}
}

func ExampleDIDResolve() {
	base := did.DID{Method: "example", SpecID: "101"}
	tests := []string{
		"/hello",
		"any?",
		"#body",
		"did:example:*",
		"http://localhost:8080",
	}

	for _, t := range tests {
		s, err := base.Resolve(t)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("• " + s)
		}
	}
	// Output:
	// • did:example:101/hello
	// • did:example:101/any
	// • did:example:101#body
	// • did:example:*
	// • http://localhost:8080
}

func FuzzParse(f *testing.F) {
	f.Add("did:a:b")
	f.Add("did:1:2%34")
	f.Fuzz(func(t *testing.T, s string) {
		_, err := did.Parse(s)
		switch e := err.(type) {
		case nil:
			break // OK
		case *did.SyntaxError:
			if e.S != s {
				t.Errorf("Parse(%q) got SyntaxError.S %q", s, e.S)
			}
		default:
			t.Errorf("got not a SyntaxError: %s", err)
		}
	})
}

func FuzzDIDString(f *testing.F) {
	f.Add("a", "b")
	f.Add("1", "2%3")
	f.Fuzz(func(t *testing.T, method, specID string) {
		// omit invalid method names for fuzz test
		if method == "" {
			return
		}
		for _, r := range method {
			if r < '0' || r > '9' && r < 'a' || r > 'z' {
				return
			}
		}

		d := did.DID{Method: method, SpecID: specID}
		s := d.String()

		d2, err := did.Parse(s)
		if err != nil {
			t.Fatalf("Parse error on String result %q: %s", s, err)
		}
		if d != d2 {
			t.Fatalf("%#v became %#v after codec cycle with %q", d, d2, s)
		}
	})
}
