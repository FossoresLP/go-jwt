package hs

import (
	"errors"

	"github.com/fossoreslp/go-jwt/publickey"
)

// Settings stores the key for an algorithm
type Settings struct {
	key []byte
	kid string
	jku string
}

// NewSettings creates new signature settings for the parameters
func NewSettings(key []byte, keyID string) (Settings, error) {
	return NewSettingsWithKeyURL(key, keyID, "")
}

// NewSettingsWithKeyURL creates new signature settings for the parameters
func NewSettingsWithKeyURL(key []byte, keyID, keyURL string) (Settings, error) {
	if len(key) == 0 {
		return Settings{}, errors.New("empty keys are not allowed")
	}
	return Settings{key, keyID, keyURL}, nil
}

// AddPublicKey adds a public key for verification
func (p *Provider) AddPublicKey(key publickey.PublicKey) error {
	id := key.GetKeyID()
	if _, ok := p.keys[id]; ok {
		return errors.New("key ID already exists")
	}
	p.keys[id] = key.GetPublicKey()
	return nil
}

// Remove public key removes a public key by it's key ID from the verification set
func (p *Provider) RemovePublicKey(keyid string) {
	if keyid == p.settings.kid {
		return
	}
	delete(p.keys, keyid)
}

// CurrentKey returns the public key belonging to the private key used for signing.
// CAUTION: The public and private key are the same for this algorithm. Do not share the key you obtain using this function
func (p Provider) CurrentKey() publickey.PublicKey {
	return publickey.New(p.settings.key, p.settings.kid)
}
