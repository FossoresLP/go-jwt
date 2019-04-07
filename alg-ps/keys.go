package ps

import (
	"crypto/rsa"
	"errors"

	"github.com/fossoreslp/go-jwt/jwk"
)

// Settings stores the key for an algorithm
type Settings struct {
	private *rsa.PrivateKey
	kid     string
	jku     string
}

// NewSettings creates new signature settings for the parameters
func NewSettings(key jwk.JWK) (Settings, error) {
	return NewSettingsWithKeyURL(key, "")
}

// NewSettingsWithKeyURL creates new signature settings for the parameters
func NewSettingsWithKeyURL(key jwk.JWK, keyURL string) (Settings, error) {
	rsaKey, err := key.GetRSAPrivateKey()
	if err != nil {
		return Settings{}, err
	}
	return Settings{rsaKey, key.GetKeyID(), keyURL}, nil
}

// AddPublicKey adds a public key for verification
func (p *Provider) AddPublicKey(key jwk.JWK) error {
	id := key.GetKeyID()
	if _, ok := p.keys[id]; ok {
		return errors.New("key ID already exists")
	}
	pub, err := key.GetRSAPublicKey()
	if err != nil {
		return err
	}
	p.keys[id] = pub
	return nil
}

// RemovePublicKey removes a public key by it's key ID from the verification set
func (p *Provider) RemovePublicKey(keyid string) {
	if keyid == p.settings.kid {
		return
	}
	delete(p.keys, keyid)
}

// CurrentKey returns the public key belonging to the private key used for signing.
func (p Provider) CurrentKey() jwk.JWK {
	return jwk.NewRSAPublicKey(&p.settings.private.PublicKey, p.settings.kid)
}
