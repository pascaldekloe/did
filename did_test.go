package did_test

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pascaldekloe/did"
)

// Example2 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-2
const example2 = "did:example:123456/path"

// Example3 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-3
const example3 = "did:example:123456?versionId=1"

// Example4 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-a-unique-verification-method-in-a-did-document
const example4 = "did:example:123#public-key-0"

// Example5 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-a-unique-service-in-a-did-document
const example5 = "did:example:123#agent"

// Example6 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-a-resource-external-to-a-did-document
const example6 = "did:example:123?service=agent&relativeRef=/credentials#degree"

// Example7 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-a-did-url-with-a-versiontime-did-parameter
const example7 = "did:example:123?versionTime=2021-05-10T17:00:00Z"

// Example8 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-a-did-url-with-a-service-and-a-relativeref-did-parameter
const example8 = "did:example:123?service=files&relativeRef=/resume.pdf"

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

var GoldenDIDErrors = []struct{ DID, Err string }{
	{"urn:issn:0-670-85668-1", `invalid DID "urn:issn:0-670-85668-1": no "did:" scheme`},
	{"bitcoin:mjSk1Ny9spzU2fouzYgLqGUD8U41iR35QN?amount=100", `invalid DID "bitcoin:mjSk1Ny9spzU2fouzYgLqGUD8U41iR35QN?amount=100": no "did:" scheme`},
	{"http://localhost/", `invalid DID "http://localhost/": no "did:" scheme`},

	{"did:", `invalid DID "did:": end incomplete`},
	{"did:foo", `invalid DID "did:foo": end incomplete`},
	{"did:foo:", `invalid DID "did:foo:": end incomplete`},
	{"did:foo:%", `invalid DID "did:foo:%": end incomplete`},
	{"did:foo:%b", `invalid DID "did:foo:%b": end incomplete`},

	{"did::bar", `invalid DID "did::bar": illegal ':' at byte № 5`},
	{"did:foo:bar:", `invalid DID "did:foo:bar:": illegal ':' at byte № 12`},
	{"did:X:bar", `invalid DID "did:X:bar": illegal 'X' at byte № 5`},
	{"did:a-1:bar", `invalid DID "did:a-1:bar": illegal '-' at byte № 6`},
	{"did:f%6Fo:bar", `invalid DID "did:f%6Fo:bar": illegal '%' at byte № 6`},

	// colon in method-specific identifier not allowed as last character
	{"did:foo::", `invalid DID "did:foo::": illegal ':' at byte № 9`},
	{"did:foo:::", `invalid DID "did:foo:::": illegal ':' at byte № 10`},
	{"did:foo:bar:", `invalid DID "did:foo:bar:": illegal ':' at byte № 12`},
	{"did:foo:bar::", `invalid DID "did:foo:bar::": illegal ':' at byte № 13`},
	{"did:foo:bar:baz:", `invalid DID "did:foo:bar:baz:": illegal ':' at byte № 16`},
	{"did:foo:%12:", `invalid DID "did:foo:%12:": illegal ':' at byte № 12`},
	{"did:foo:%3A:", `invalid DID "did:foo:%3A:": illegal ':' at byte № 12`},

	{"did:foo:bar:", `invalid DID "did:foo:bar:": illegal ':' at byte № 12`},
	{"did:foo:bar:,", `invalid DID "did:foo:bar:,": illegal ',' at byte № 13`},
	{"did:foo:bar:%X0", `invalid DID "did:foo:bar:%X0": illegal 'X' at byte № 14`},
	{"did:foo:bar:%0Y", `invalid DID "did:foo:bar:%0Y": illegal 'Y' at byte № 15`},

	{"did:long" + strings.Repeat("g", 1000), `invalid DID "did:longggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg…" [truncated]: end incomplete`},
	{"did:long" + strings.Repeat("g", 1000) + ":~", `invalid DID "did:longggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg…" [truncated]: illegal '~' at byte № 1010`},
}

func TestParseErrors(t *testing.T) {
	for _, gold := range GoldenDIDErrors {
		got, err := did.Parse(gold.DID)
		switch err.(type) {
		case nil:
			t.Errorf("%q got %+v, want SyntaxError %q", gold.DID, got, gold.Err)
		case *did.SyntaxError:
			if s := err.Error(); s != gold.Err {
				t.Errorf("%q got error %q, want %q", gold.DID, s, gold.Err)
			}
		default:
			t.Errorf("%q got error type %T (%q), want a *did.SyntaxError", gold.DID, err, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add("did:a:b")
	f.Add("did:cd:%01%eF")
	f.Fuzz(func(t *testing.T, s string) {
		_, err := did.Parse(s)
		switch e := err.(type) {
		case nil:
			break // OK
		case *did.SyntaxError:
			if e.S != s {
				t.Errorf("Parse(%q) got SyntaxError.S %q", s, e.S)
			}
			e.Error()
		default:
			t.Errorf("got not a SyntaxError: %s", err)
		}
	})
}

var GoldenDIDs = []struct {
	S string
	did.DID
}{
	{
		"did:foo:bar",
		did.DID{Method: "foo", SpecID: "bar"},
	}, {
		"did:foo:b%61r",
		did.DID{Method: "foo", SpecID: "bar"},
	}, {
		"did:c:str%00",
		did.DID{Method: "c", SpecID: "str\x00"},
	}, {
		"did:a:b:c",
		did.DID{Method: "a", SpecID: "b:c"},
	}, {
		"did:a:b%3Ac",
		did.DID{Method: "a", SpecID: "b:c"},
	}, {
		"did:a::c",
		did.DID{Method: "a", SpecID: ":c"},
	}, {
		"did:a:%3Ac",
		did.DID{Method: "a", SpecID: ":c"},
	}, {
		"did:a:::c",
		did.DID{Method: "a", SpecID: "::c"},
	}, {
		"did:h:%12:%34",
		did.DID{Method: "h", SpecID: "\x12:\x34"},
	}, {
		"did:x:%3A",
		did.DID{Method: "x", SpecID: ":"},
	}, {
		"did:xx::%3A",
		did.DID{Method: "xx", SpecID: "::"},
	}, {
		"did:x:%3A%3A",
		did.DID{Method: "xxx", SpecID: "::"},
	},
}

func TestDIDString(t *testing.T) {
	if got := new(did.DID).String(); got != "" {
		t.Errorf("the zero value got %q, want an empty string", got)
	}

	for _, gold := range GoldenDIDs {
		var got string
		n := testing.AllocsPerRun(1, func() {
			got = gold.DID.String()
		})
		if n != 1 {
			t.Errorf("%#v String did %f memory allocations, want 1", gold.DID, n)
		}
		if !gold.DID.Equal(got) {
			t.Errorf("%#v String got %q, want Equal to self", gold.DID, got)
		}
	}
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
	{
		// binary value
		"did:sha256:%e3%b0%c4%42%98%fc%1c%14%9a%fb%f4%c8%99%6f%b9%24%27%ae%41%e4%64%9b%93%4c%a4%95%99%1b%78%52%b8%55",
		// upper- and lower-case mix
		"did:sha256:%E3%b0%c4%42%98%Fc%1c%14%9a%fB%f4%c8%99%6f%b9%24%27%ae%41%e4%64%9b%93%4c%a4%95%99%1b%78%52%b8%55",
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

func ExampleDID_ResolveReference() {
	base := did.DID{Method: "example", SpecID: "101"}
	tests := []string{
		"/hello",
		"any?",
		"#body",
		"did:example:2",
		"did:foo:bar",
		"http://localhost:8080",
	}

	for _, t := range tests {
		s, err := base.ResolveReference(t)
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
	// • did:example:2
	// • did:foo:bar
	// • http://localhost:8080
}

var GoldenURLs = []struct {
	S string
	did.URL
}{
	{
		"did:example:123456789abcdefghi",
		did.URL{
			DID: did.DID{
				Method: "example",
				SpecID: "123456789abcdefghi",
			},
		},
	}, {
		example2,
		did.URL{
			DID: did.DID{
				Method: "example",
				SpecID: "123456",
			},
			RawPath: "/path",
		},
	}, {
		example3,
		did.URL{
			DID: did.DID{
				Method: "example",
				SpecID: "123456",
			},
			Query: url.Values{"versionId": []string{"1"}},
		},
	}, {
		example4,
		did.URL{
			DID: did.DID{
				Method: "example",
				SpecID: "123",
			},
			Fragment: "public-key-0",
		},
	}, {
		example5,
		did.URL{
			DID: did.DID{
				Method: "example",
				SpecID: "123",
			},
			Fragment: "agent",
		},
	}, {
		example6,
		did.URL{
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
	}, {
		example7,
		did.URL{
			DID: did.DID{
				Method: "example",
				SpecID: "123",
			},
			Query: url.Values{"versionTime": []string{"2021-05-10T17:00:00Z"}},
		},
	}, {
		example8,
		did.URL{
			DID: did.DID{
				Method: "example",
				SpecID: "123",
			},
			Query: url.Values{"service": []string{"files"},
				"relativeRef": []string{"/resume.pdf"},
			},
		},
	}, {
		"did:foo:bar:baz",
		did.URL{
			DID: did.DID{
				Method: "foo",
				SpecID: "bar:baz",
			},
		},
	},

	{"#", did.URL{}},
	{"?", did.URL{}},
	{"?#", did.URL{}},

	{".", did.URL{RawPath: "."}},
	{"./", did.URL{RawPath: "./"}},
	{"./..", did.URL{RawPath: "./.."}},
	{"./../", did.URL{RawPath: "./../"}},
	{"./../...", did.URL{RawPath: "./../..."}},
	{".#", did.URL{RawPath: "."}},
	{"./#", did.URL{RawPath: "./"}},
	{"./..#", did.URL{RawPath: "./.."}},
	{"./../#", did.URL{RawPath: "./../"}},
	{"./../...#", did.URL{RawPath: "./../..."}},
	{".?", did.URL{RawPath: "."}},
	{"./?", did.URL{RawPath: "./"}},
	{"./..?", did.URL{RawPath: "./.."}},
	{"./../?", did.URL{RawPath: "./../"}},
	{"./../...?", did.URL{RawPath: "./../..."}},

	{"did", did.URL{RawPath: "did"}},
	{"did/", did.URL{RawPath: "did/"}},
	{"did/a", did.URL{RawPath: "did/a"}},
	{"/did:a", did.URL{RawPath: "/did:a"}},
	{"/did:a/", did.URL{RawPath: "/did:a/"}},
	{"/did:a/did", did.URL{RawPath: "/did:a/did"}},

	{"?foo=bar", did.URL{Query: url.Values{"foo": []string{"bar"}}}},
	{"#foo", did.URL{Fragment: "foo"}},
}

func TestParseURL(t *testing.T) {
	for _, gold := range GoldenURLs {
		got, err := did.ParseURL(gold.S)
		if err != nil {
			t.Errorf("DID %q got error: %s", gold.S, err)
			continue
		}

		if got.Method != gold.Method {
			t.Errorf("DID %q got method %q, want %q", gold.S, got.Method, gold.Method)
		}
		if got.SpecID != gold.SpecID {
			t.Errorf("DID %q got method-specific identifier %q, want %q", gold.S, got.SpecID, gold.SpecID)
		}
		if got.RawPath != gold.RawPath {
			t.Errorf("DID %q got raw path %q, want %q", gold.S, got.RawPath, gold.RawPath)
		}
		if !reflect.DeepEqual(got.Query, gold.Query) {
			t.Errorf("DID %q got params %q, want %q", gold.S, got.Query, gold.Query)
		}
		if got.Fragment != gold.Fragment {
			t.Errorf("DID %q got fragment %q, want %q", gold.S, got.Fragment, gold.Fragment)
		}
	}
}

var GoldenURLErrors = []struct{ URL, Err string }{
	{"did:foo:bar/%", `invalid DID "did:foo:bar/%": end incomplete`},
	{"did:foo:bar/%X0", `invalid DID "did:foo:bar/%X0": illegal 'X' at byte № 14`},
}

func TestParseURLErrors(t *testing.T) {
	// ParseURL should give the same error as Parse for plain DIDs.
	for _, gold := range GoldenDIDErrors {
		got, err := did.ParseURL(gold.DID)
		switch err.(type) {
		case nil:
			t.Errorf("%q got %+v, want SyntaxError %q", gold.DID, got, gold.Err)
		case *did.SyntaxError:
			if s := err.Error(); s != gold.Err {
				t.Errorf("%q got error %q, want %q", gold.DID, s, gold.Err)
			}
		default:
			t.Errorf("%q got error type %T (%q), want a *did.SyntaxError", gold.DID, err, err)
		}
	}

	for _, gold := range GoldenURLErrors {
		got, err := did.ParseURL(gold.URL)
		switch err.(type) {
		case nil:
			t.Errorf("%q got %+v, want SyntaxError %q", gold.URL, got, gold.Err)
		case *did.SyntaxError:
			if s := err.Error(); s != gold.Err {
				t.Errorf("%q got error %q, want %q", gold.URL, s, gold.Err)
			}
		default:
			t.Errorf("%q got error type %T (%q), want a *did.SyntaxError", gold.URL, err, err)
		}
	}

	const URL = "did:foo:bar#%X0"
	got, err := did.ParseURL(URL)
	switch err.(type) {
	case nil:
		t.Errorf("%q got %+v, want a SyntaxError", URL, got)
	case *did.SyntaxError:
		if !errors.As(err, new(url.EscapeError)) {
			t.Errorf("%q got error %#v, want a wrapped url.EscapeError", URL, err)
		}
	default:
		t.Errorf("%q got error type %T (%q), want a *did.SyntaxError", URL, err, err)
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
	{
		"#escaped=%F0%9F%A4%96",
		"#%65scaped=%F0%9F%A4%96",
		"#escap%65d=%F0%9F%A4%96",
	},
	{
		"/%ee?%aa=%bb#%ff",
		"/%eE?%aA=%bB#%fF",
		"/%Ee?%Aa=%Bb#%Ff",
		"/%EE?%AA=%BB#%FF",
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
		{"/%AB/%ba/", []string{"\xab", "\xba"}},
		{"/%cD/%Dc/", []string{"\xcd", "\xdc"}},
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
		if name, _ := vTime.Zone(); name != "UTC" {
			t.Errorf("%s got time zone %q, want UTC", sample, name)
		}
	})
}
