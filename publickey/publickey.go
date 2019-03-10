package publickey

// PublicKey represents a public key
type PublicKey struct {
	key []byte
	kid string
}

// New returns a new PublicKey with the arguments as values
func New(key []byte, id string) PublicKey {
	return PublicKey{key, id}
}

// GetPublicKey returns the key as a byte slice
func (s PublicKey) GetPublicKey() []byte {
	return s.key
}

// GetKeyID returns the keys ID
func (s PublicKey) GetKeyID() string {
	return s.kid
}
