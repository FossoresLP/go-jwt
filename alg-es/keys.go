package es

import (
	"crypto/ecdsa"
	"errors"

	"github.com/fossoreslp/go-jwt/jwk"
)

// Settings stores the signature settings for an EdDSA curve
type Settings struct {
	private *ecdsa.PrivateKey
	kid     string
	jku     string
}

// NewSettings creates new signature settings for the parameters
func NewSettings(key jwk.JWK) (Settings, error) {
	return NewSettingsWithKeyURL(key, "")
}

// NewSettingsWithKeyURL creates new signature settings for the parameters
func NewSettingsWithKeyURL(key jwk.JWK, keyurl string) (Settings, error) {
	priv, err := key.GetECPrivateKey()
	if err != nil {
		return Settings{}, err
	}
	return Settings{priv, key.GetKeyID(), keyurl}, nil
}

// AddPublicKey adds a public key for verification
func (p *Provider) AddPublicKey(key jwk.JWK) error {
	id := key.GetKeyID()
	if _, ok := p.keys[id]; ok {
		return errors.New("key ID already exists")
	}
	k, err := key.GetECPublicKey()
	if err != nil {
		return err
	}
	p.keys[id] = k
	return nil
}

// RemovePublicKey removes a public key by it's key ID from the verification set
func (p *Provider) RemovePublicKey(keyid string) {
	if keyid == p.settings.kid {
		return
	}
	delete(p.keys, keyid)
}

// CurrentKey returns the public key belonging to the private key used for signing
func (p Provider) CurrentKey() jwk.JWK {
	k, _ := jwk.NewECPublicKey(&p.settings.private.PublicKey, p.settings.kid)
	return k
}
