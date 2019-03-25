package ps

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/fossoreslp/go-jwt/publickey"
)

// Settings stores the key for an algorithm
type Settings struct {
	private *rsa.PrivateKey
	kid     string
	jku     string
}

// NewSettings creates new signature settings for the parameters
func NewSettings(key []byte, keyID string) (Settings, error) {
	return NewSettingsWithKeyURL(key, keyID, "")
}

// NewSettingsWithKeyURL creates new signature settings for the parameters
func NewSettingsWithKeyURL(key []byte, keyID, keyURL string) (Settings, error) {
	rsaKey, err := x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		k, err := x509.ParsePKCS8PrivateKey(key)
		if err != nil {
			return Settings{}, errors.New("could not decode private key as either PKCS1 or PKCS8")
		}
		castKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return Settings{}, errors.New("PKCS8 does not contain a RSA private key")
		}
		rsaKey = castKey
	}
	return Settings{rsaKey, keyID, keyURL}, nil
}

// AddPublicKey adds a public key for verification
func (p *Provider) AddPublicKey(key publickey.PublicKey) error {
	id := key.GetKeyID()
	if _, ok := p.keys[id]; ok {
		return errors.New("key ID already exists")
	}
	pub, err := x509.ParsePKIXPublicKey(key.GetPublicKey())
	if err != nil {
		return errors.New("could not decode public key")
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("public key is not a RSA public key")
	}
	p.keys[id] = rsaKey
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
func (p Provider) CurrentKey() publickey.PublicKey {
	b, _ := x509.MarshalPKIXPublicKey(&p.settings.private.PublicKey) // Marshaling an RSA public key should never fail
	return publickey.New(b, p.settings.kid)
}
