package es

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"

	"github.com/fossoreslp/go-jwt/publickey"
)

// KeySet stores the key for an algorithm
type KeySet struct {
	private   *ecdsa.PrivateKey
	public    *ecdsa.PublicKey
	kid       string
	jku       string
	canSign   bool
	canVerify bool
}

// SetKeys sets the key
func (ks *KeySet) SetKeys(priv, pub []byte) error {
	if priv != nil {
		key, err := x509.ParseECPrivateKey(priv)
		if err != nil {
			k, err := x509.ParsePKCS8PrivateKey(priv)
			if err != nil {
				return errors.New("could not decode private key as either EC or PKCS8")
			}
			ecKey, ok := k.(*ecdsa.PrivateKey)
			if !ok {
				return errors.New("PKCS8 does not contain an ECDSA private key")
			}
			key = ecKey
		}
		ks.private = key
		ks.canSign = true
	}
	if pub != nil {
		key, err := x509.ParsePKIXPublicKey(pub)
		if err != nil {
			return errors.New("could not decode public key")
		}
		ecdsaKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("public key is not an ECDSA public key")
		}
		ks.public = ecdsaKey
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
	key, err := x509.MarshalPKIXPublicKey(ks.public)
	if err != nil {
		return publickey.PublicKey{}
	}
	return publickey.New(key, ks.kid)
}
