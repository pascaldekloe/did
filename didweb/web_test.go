package didweb_test

import (
	"errors"
	"fmt"

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
