package did

// Doc holds the “core properties” of a DID document.
type Doc struct {
	Subject Attrs `json:"id"`
}
