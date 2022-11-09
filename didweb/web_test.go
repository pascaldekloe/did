package didweb_test

import (
	"errors"
	"fmt"

	"github.com/pascaldekloe/did"
	"github.com/pascaldekloe/did/didweb"
)

func ExampleClient_Resolve() {
	doc, _, err := new(didweb.Client).Resolve("https://api.preprod.ebsi.eu/did-registry/v3/identifiers/did:ebsi:zqwtmBuhZoANA2YzwPL7jf4")
	switch {
	case err == nil:
		fmt.Println("got DID", doc.Subject)
	case errors.Is(err, did.ErrNotFound):
		fmt.Println("test transaction from EBSI pre-production unavailable")
	default:
		fmt.Println(err)
	}
	// Output:
	// got DID did:ebsi:zqwtmBuhZoANA2YzwPL7jf4
}
