package did_test

import (
	"fmt"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/pascaldekloe/did"
)

// Example3 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-3
var example3 = "did:example:123456?versionId=1"

// Example7 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-a-did-url-with-a-versiontime-did-parameter
var example7 = "did:example:123?versionTime=2021-05-10T17:00:00Z"

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

// DIDEquals groups equivalent DIDs.
var DIDEquals = [][]string{
	{
		"did:example:escaped%F0%9F%A4%96",
		"did:example:%65scaped%F0%9F%A4%96",
		"did:example:escap%65d%F0%9F%A4%96",
	},
	{
		"did:tricky:%3Afoo%2F",
		"did:tricky:%3A%66%6F%6F%2F",
	},
}

func TestDIDEqual(t *testing.T) {
	for i, equals := range DIDEquals {
		for _, s := range equals {
			d, err := did.Parse(s)
			if err != nil {
				t.Fatalf("Parse(%q) error: %s", s, err)
			}

			// compare all groups
			for j, equals := range DIDEquals {
				want := i == j // same group

				// compare each entry, including self
				for _, e := range equals {
					got := d.Equal(e)
					if got != want {
						t.Errorf("Parse(%q) Equal(%q) got %t, want %t\nparsed as %#v", s, e, got, want, d)
					}
				}
			}
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
	example3: {
		DID: did.DID{
			Method: "example",
			SpecID: "123456",
		},
		Query: url.Values{"versionId": []string{"1"}},
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
		Query: url.Values{
			"service":     []string{"agent"},
			"relativeRef": []string{"/credentials"},
		},
		Fragment: "degree",
	},
	example7: {
		DID: did.DID{
			Method: "example",
			SpecID: "123",
		},
		Query: url.Values{"versionTime": []string{"2021-05-10T17:00:00Z"}},
	},
	"did:example:123?service=files&relativeRef=/resume.pdf": {
		DID: did.DID{
			Method: "example",
			SpecID: "123",
		},
		Query: url.Values{"service": []string{"files"},
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
		if !reflect.DeepEqual(got.Query, want.Query) {
			t.Errorf("DID %q got params %q, want %q", s, got.Query, want.Query)
		}
		if got.Fragment != want.Fragment {
			t.Errorf("DID %q got fragment %q, want %q", s, got.Fragment, want.Fragment)
		}
	}
}

// SelectEquals groups equivalent DID URL additions.
var SelectEquals = [][]string{
	{
		"/escaped%F0%9F%A4%96",
		"/%65scaped%F0%9F%A4%96",
		"/escap%65d%F0%9F%A4%96",
	},
	{
		"#escaped%F0%9F%A4%96",
		"#%65scaped%F0%9F%A4%96",
		"#escap%65d%F0%9F%A4%96",
	},
}

var URLEquals = func() [][]string {
	// compile equality groups from DIDEquals and SelectEquals
	var groups [][]string
	for _, DIDs := range DIDEquals {
		for _, selects := range SelectEquals {
			// apply each selection on each DID
			equals := make([]string, 0, len(DIDs)*len(selects))
			for _, d := range DIDs {
				for _, sel := range selects {
					equals = append(equals, d+sel)
				}
			}

			groups = append(groups, equals)
		}
	}
	return groups
}()

func TestURLEqual(t *testing.T) {
	for i, equals := range URLEquals {
		for _, s := range equals {
			u, err := did.ParseURL(s)
			if err != nil {
				t.Fatalf("ParseURL(%q) error: %s", s, err)
			}

			// compare all groups
			for j, equals := range URLEquals {
				want := i == j // same group

				// compare each entry, including self
				for _, e := range equals {
					got := u.Equal(e)
					if got != want {
						t.Errorf("ParseURL(%q) Equal(%q) got %t, want %t\nparsed as %#v", s, e, got, want, u)
					}
				}
			}
		}
	}
}

func ExampleURL_PathWithEscape() {
	u, err := did.ParseURL("did:example:123456/path%2Fesc")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(u.PathWithEscape('\\'))
	// Output: /path\/esc
}

func TestURLPathWithEscape(t *testing.T) {
	tests := []struct{ raw, want string }{
		{"", ""},
		{"/", "/"},
		{"//", "//"},
		{"/foo", "/foo"},
		{"/%66oo", "/foo"},
		{"/f%6Fo", "/foo"},
		{"/fo%6F", "/foo"},
		{"/%66%6F%6F", "/foo"},
		{"/foo/", "/foo/"},

		{"%2F", `\/`},
		{"%2F%2F", `\/\/`},
		{"%2Ffoo", `\/foo`},
		{"/foo%2F", `/foo\/`},
		{"%2F%66%6F%6F%2F", `\/foo\/`},

		{"%5C", `\\`},
		{"/%5C", `/\\`},
		{"%5C/", `\\/`},

		// broken encodings
		{"/mis1%1", "/mis1%1"},
		{"/mis2%", "/mis2%"},
		{"%fF%Ff", "%fF%Ff"},
	}

	for _, test := range tests {
		u := did.URL{RawPath: test.raw}
		got := u.PathWithEscape('\\')
		if got != test.want {
			t.Errorf("raw path %q got %q, want %q", test.raw, got, test.want)
		}
	}
}

func FuzzURLPathWithEscape(f *testing.F) {
	f.Add("-", byte('-'))
	f.Add("%2F", byte('\\'))
	f.Add("%", byte('1'))
	f.Fuzz(func(t *testing.T, rawPath string, escape byte) {
		u := did.URL{RawPath: rawPath}
		u.PathWithEscape(escape)
		// should simply not crash
	})
}

func ExampleURL_PathSegments() {
	u := did.URL{RawPath: "/plain/and%2For/escaped%20%E2%9C%A8"}
	fmt.Printf("segmented: %q\n", u.PathSegments())
	// Output: segmented: ["plain" "and/or" "escaped ✨"]
}

func ExampleURL_SetPathSegments() {
	var u did.URL
	u.SetPathSegments("plain", "and/or", "escaped ✨")
	fmt.Printf("raw path: %q\n", u.RawPath)
	// Output: raw path: "/plain/and%2For/escaped%20%E2%9C%A8"
}

func TestURLPathSegments(t *testing.T) {
	tests := []struct {
		rawPath string
		want    []string
	}{
		{"", nil},
		{"/", []string{}},
		{"//", []string{""}},
		{"/a", []string{"a"}},
		{"/a/", []string{"a"}},
		{"/a//", []string{"a", ""}},
		{"//b/", []string{"", "b"}},
		{"///", []string{"", ""}},
	}
	for _, test := range tests {
		got := (&did.URL{RawPath: test.rawPath}).PathSegments()
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("raw path %q got %q, want %q", test.rawPath, got, test.want)
		}
	}
}

// FuzzURLSetPathSegments validates the SetPathSegments–GetPathSegments round-
// trip for losslessness.
func FuzzURLSetPathSegments(f *testing.F) {
	// Fuzz does not support []string yet
	f.Add("", "/", "")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		testURLSetPathSegments(t, a)
		testURLSetPathSegments(t, a, b)
		testURLSetPathSegments(t, a, b, c)
	})
}

func testURLSetPathSegments(t *testing.T, segs ...string) {
	var u did.URL
	u.SetPathSegments(segs...)
	got := u.PathSegments()
	if len(got) != len(segs) {
		t.Logf("set segments %q got raw path %q", segs, u.RawPath)
		t.Errorf("got %d segments %q, want %d %q", len(got), got, len(segs), segs)
		return
	}
	for i, s := range segs {
		if s != got[i] {
			t.Logf("set segments %q got raw path %q", segs, u.RawPath)
			t.Errorf("segment № %d got %q, want %q", i, got[i], s)
		}
	}
}

func TestURLVersionParams(t *testing.T) {
	t.Run("ID", func(t *testing.T) {
		sample := example3
		const want = "1"

		u, err := did.ParseURL(sample)
		if err != nil {
			t.Fatalf("%s parse error: %s", sample, err)
		}

		vID, vTime, err := u.VersionParams()
		if err != nil {
			t.Fatalf("%s got error: %s", sample, err)
		}
		if vID != want {
			t.Errorf("%s got ID %q, want %q", sample, vID, want)
		}
		if !vTime.IsZero() {
			t.Errorf("%s got time %s, want zero", sample, vTime)
		}
	})

	t.Run("time", func(t *testing.T) {
		sample := example7
		want := time.Date(2021, 05, 10, 17, 00, 00, 0, time.UTC)

		u, err := did.ParseURL(sample)
		if err != nil {
			t.Fatalf("%s parse error: %s", sample, err)
		}

		vID, vTime, err := u.VersionParams()
		if err != nil {
			t.Fatalf("%s got error: %s", sample, err)
		}
		if vID != "" {
			t.Errorf("%s got ID %q, want zero", sample, vID)
		}
		if !vTime.Equal(want) {
			t.Errorf("%s got time %s, want %s", sample, vTime, want)
		}
	})
}
