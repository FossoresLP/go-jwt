package es

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"

	"github.com/fossoreslp/go-jwt/publickey"
)

// Settings stores the signature settings for an EdDSA curve
type Settings struct {
	private *ecdsa.PrivateKey
	kid     string
	jku     string
}

// NewSettings creates new signature settings for the parameters
func NewSettings(key []byte, keyid string) (Settings, error) {
	return NewSettingsWithKeyURL(key, keyid, "")
}

// NewSettingsWithKeyURL creates new signature settings for the parameters
func NewSettingsWithKeyURL(key []byte, keyid, keyurl string) (Settings, error) {
	priv, err := x509.ParseECPrivateKey(key)
	if err != nil {
		k, err := x509.ParsePKCS8PrivateKey(key)
		if err != nil {
			return Settings{}, errors.New("could not decode private key as either EC or PKCS8")
		}
		ecKey, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return Settings{}, errors.New("PKCS8 does not contain an ECDSA private key")
		}
		priv = ecKey
	}
	return Settings{priv, keyid, keyurl}, nil
}

// AddPublicKey adds a public key for verification
func (p *Provider) AddPublicKey(key publickey.PublicKey) error {
	id := key.GetKeyID()
	if _, ok := p.keys[id]; ok {
		return errors.New("key ID already exists")
	}
	enc := key.GetPublicKey()
	k, err := x509.ParsePKIXPublicKey(enc)
	if err != nil {
		return errors.New("could not decode public key")
	}
	ecdsaKey, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("public key is not an ECDSA public key")
	}
	p.keys[id] = ecdsaKey
	return nil
}

// Remove public key removes a public key by it's key ID from the verification set
func (p *Provider) RemovePublicKey(keyid string) {
	if keyid == p.settings.kid {
		return
	}
	delete(p.keys, keyid)
}

// CurrentKey returns the public key belonging to the private key used for signing
func (p Provider) CurrentKey() publickey.PublicKey {
	key, _ := x509.MarshalPKIXPublicKey(&p.settings.private.PublicKey) // No need to check error as marshaling an EC public key can only fail for an unsupported curve which cannot be introduced as it would fail to unmarshal.
	return publickey.New(key, p.settings.kid)
}
