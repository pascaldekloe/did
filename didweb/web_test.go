package didweb_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pascaldekloe/did"
	"github.com/pascaldekloe/did/didweb"
)

func ExampleClient_Resolve() {
	doc, _, err := new(didweb.Client).Resolve("https://identity.foundation/.well-known/did.json")
	switch {
	case err == nil:
		fmt.Println("got DID", doc.Subject)
	case errors.Is(err, did.ErrNotFound):
		fmt.Println("DIF .well-known DID not found")
	default:
		fmt.Println(err)
	}
	// Output:
	// got DID did:web:identity.foundation
}

func TestHTTPNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		io.WriteString(w, "arbitrary")
	}))
	defer srv.Close()

	_, _, err := new(didweb.Client).Resolve(srv.URL)
	if err == nil {
		t.Fatal("no error on Resolve")
	}
	if !errors.Is(err, did.ErrNotFound) {
		t.Errorf("got error %v, want did.ErrNotFound", err)
	}
}

func TestHTTPNotAcceptable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(406)
		io.WriteString(w, "arbitrary")
	}))
	defer srv.Close()

	_, _, err := new(didweb.Client).Resolve(srv.URL)
	if err == nil {
		t.Fatal("no error on Resolve")
	}
	if !errors.Is(err, did.ErrMediaType) {
		t.Errorf("got error %v, want did.ErrMediaType", err)
	}
}

func TestHTTPGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(410)
		io.WriteString(w, "arbitrary")
	}))
	defer srv.Close()

	_, _, err := new(didweb.Client).Resolve(srv.URL)
	if err == nil {
		t.Fatal("no error on Resolve")
	}
	want := `HTTP "410 Gone" for DID document ` + srv.URL
	if got := err.Error(); got != want {
		t.Errorf("got error %q, want %q", got, want)
	}
}

func TestJSONErrorCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, `{"error": "invalidDid"}`)
	}))
	defer srv.Close()

	_, _, err := new(didweb.Client).Resolve(srv.URL)
	if err == nil {
		t.Fatal("no error on Resolve")
	}
	if !errors.Is(err, did.ErrInvalid) {
		t.Errorf("got error %v, want did.ErrInvalid", err)
	}
}
