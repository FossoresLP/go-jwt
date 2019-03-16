package rs

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/fossoreslp/go-jwt/publickey"
)

// KeySet stores the key for an algorithm
type KeySet struct {
	private   *rsa.PrivateKey
	public    *rsa.PublicKey
	kid       string
	jku       string
	canSign   bool
	canVerify bool
}

// SetKeys sets the key
func (ks *KeySet) SetKeys(priv, pub []byte) error {
	if priv != nil {
		key, err := x509.ParsePKCS1PrivateKey(priv)
		if err != nil {
			k, err := x509.ParsePKCS8PrivateKey(priv)
			if err != nil {
				return errors.New("could not decode private key as either PKCS1 or PKCS8")
			}
			rsaKey, ok := k.(*rsa.PrivateKey)
			if !ok {
				return errors.New("PKCS8 does not contain a RSA private key")
			}
			key = rsaKey
		}
		ks.private = key
		ks.canSign = true
	}
	if pub != nil {
		key, err := x509.ParsePKIXPublicKey(pub)
		if err != nil {
			return errors.New("could not decode public key")
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("public key is not a RSA public key")
		}
		ks.public = rsaKey
		ks.canVerify = true
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

// GetPublicKey returns the public key of the keyset
func (ks KeySet) GetPublicKey() publickey.PublicKey {
	if ks.public == nil {
		return publickey.PublicKey{}
	}
	b, err := x509.MarshalPKIXPublicKey(ks.public)
	if err != nil {
		return publickey.PublicKey{}
	}
	return publickey.New(b, ks.kid)
}
