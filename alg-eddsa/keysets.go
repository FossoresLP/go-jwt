package eddsa

import (
	"errors"

	"github.com/fossoreslp/go-jwt/publickey"
	"golang.org/x/crypto/ed25519"
)

// Ed25519KeySet stores a set of Ed25519 public and private keys
type Ed25519KeySet struct {
	private   ed25519.PrivateKey
	public    ed25519.PublicKey
	kid       string
	jku       string
	canSign   bool
	canVerify bool
}

// SetKeys sets the keys of the key set
func (ks *Ed25519KeySet) SetKeys(priv, pub []byte) error {
	if priv != nil {
		if len(priv) != ed25519.PrivateKeySize {
			return errors.New("private key has wrong size")
		}
		ks.private = ed25519.PrivateKey(priv)
		ks.canSign = true
	}
	if pub != nil {
		if len(pub) != ed25519.PublicKeySize {
			return errors.New("public key has wrong size")
		}
		ks.public = ed25519.PublicKey(pub)
		ks.canVerify = true
	}
	return nil
}

// SetKeyID sets the key id of the key set
func (ks *Ed25519KeySet) SetKeyID(kid string) {
	ks.kid = kid
}

// SetKeyURL sets the key url of the key set
func (ks *Ed25519KeySet) SetKeyURL(jku string) {
	ks.jku = jku
}

// GetPublicKey returns the public key of the keyset
func (ks Ed25519KeySet) GetPublicKey() publickey.PublicKey {
	return publickey.New([]byte(ks.public), ks.kid)
}

// Ed448KeySet stores a set of Ed448 public and private keys
type Ed448KeySet struct {
	private   [144]byte
	public    [56]byte
	kid       string
	jku       string
	canSign   bool
	canVerify bool
}

// SetKeys sets the keys of the key set
func (ks *Ed448KeySet) SetKeys(priv, pub []byte, kid string) error {
	if priv != nil {
		if len(priv) != 144 {
			return errors.New("private key has wrong size")
		}
		copy(ks.private[:], priv)
		ks.canSign = true
	}
	if pub != nil {
		if len(pub) != 56 {
			return errors.New("public key has wrong size")
		}
		copy(ks.public[:], pub)
		ks.canVerify = true
	}
	return nil
}

// SetKeyID sets the key id of the key set
func (ks *Ed448KeySet) SetKeyID(kid string) {
	ks.kid = kid
}

// SetKeyURL sets the key url of the key set
func (ks *Ed448KeySet) SetKeyURL(jku string) {
	ks.jku = jku
}

// GetPublicKey returns the public key of the keyset
func (ks Ed448KeySet) GetPublicKey() publickey.PublicKey {
	return publickey.New(ks.public[:], ks.kid)
}
