package did

// Doc holds the “core properties” of a DID document.
type Doc struct {
	Subject DID `json:"id"`
}
