package hs

import (
	"errors"
)

// KeySet stores the key for an algorithm
type KeySet struct {
	key []byte
	kid string
	jku string
}

// SetKeys sets the key (in this package only the private key is used)
func (ks *KeySet) SetKeys(priv, pub []byte) error {
	if len(priv) == 0 {
		return errors.New("empty keys are not allowed")
	}
	return nil
}

// SetKeyID sets the key id of the key set
func (ks *KeySet) SetKeyID(kid string) {
	ks.kid = kid
}

// SetKeyURL sets the key url of the key set
func (ks *KeySet) SetKeyURL(jku string) {
	ks.jku = jku
}

// GetPublicKey returns the public key of the keyset (in this package the is only one key - to not share it publically or everyone else will be able to create authentic signatures)
func (ks KeySet) GetPublicKey() PublicKey {
	return PublicKey{ks.key, ks.kid}
}

// PublicKey represents a public key
type PublicKey struct {
	key []byte
	kid string
}

// GetPublicKey returns the key as a byte slice
func (s PublicKey) GetPublicKey() []byte {
	return s.key
}

// GetKeyID returns the keys ID
func (s PublicKey) GetKeyID() string {
	return s.kid
}
