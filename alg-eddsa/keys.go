package eddsa

import (
	"errors"

	"github.com/fossoreslp/go-jwt/publickey"
	"github.com/fossoreslp/go-uuid-v4"
	"github.com/otrv4/ed448"
	"golang.org/x/crypto/ed25519"
)

// AddPublicKey adds a public key for verification
func (p *Provider) AddPublicKey(key publickey.PublicKey) error {
	id := key.GetKeyID()
	enc := key.GetPublicKey()
	if len(enc) == ed25519.PublicKeySize {
		if _, ok := p.c2[id]; ok {
			return errors.New("key ID already exists")
		}
		p.c2[id] = ed25519.PublicKey(enc)
		return nil
	}
	if len(enc) == 56 {
		if _, ok := p.c4[id]; ok {
			return errors.New("key ID already exists")
		}
		var pub [56]byte
		copy(pub[:], enc)
		p.c4[id] = pub
		return nil
	}
	return errors.New("key has invalid length")
}

// RemovePublicKey removes a public key by it's key ID from the verification set
func (p *Provider) RemovePublicKey(keyid string) {
	if keyid == p.settings.kid {
		return
	}
	delete(p.c2, keyid)
	delete(p.c4, keyid)
}

// CurrentKey returns the public key belonging to the private key used for signing
func (p Provider) CurrentKey() publickey.PublicKey {
	if p.curve == Ed25519 {
		return publickey.New(p.c2[p.settings.kid], p.settings.kid)
	}
	if p.curve == Ed448 {
		k := p.c4[p.settings.kid]
		return publickey.New(k[:], p.settings.kid)
	}
	return publickey.PublicKey{}
}

func generateEd25519Keys() (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, "", err
	}
	id, err := uuid.NewString()
	if err != nil {
		return nil, nil, "", err
	}
	return priv, pub, id, nil
}

func generateEd448Keys() ([144]byte, [56]byte, string, error) {
	curve := ed448.NewCurve()
	priv, pub, ok := curve.GenerateKeys()
	if !ok {
		return [144]byte{0x0}, [56]byte{0x0}, "", errors.New("failed to generate Ed448 keys")
	}
	id, err := uuid.NewString()
	if err != nil {
		return [144]byte{0x0}, [56]byte{0x0}, "", err
	}
	return priv, pub, id, nil
}
