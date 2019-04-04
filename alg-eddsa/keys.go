package eddsa

import (
	"errors"

	"github.com/fossoreslp/go-jwt/jwk"
	"github.com/fossoreslp/go-uuid-v4"
	"github.com/otrv4/ed448"
	"golang.org/x/crypto/ed25519"
)

// Settings stores the signature settings for an EdDSA curve
type Settings struct {
	typ     int
	ed25519 ed25519.PrivateKey
	ed448   [144]byte
	kid     string
	jku     string
}

// NewSettings creates new signature settings for the parameters
func NewSettings(key jwk.JWK) (Settings, error) {
	return NewSettingsWithKeyURL(key, "")
}

// NewSettingsWithKeyURL creates new signature settings for the parameters
func NewSettingsWithKeyURL(key jwk.JWK, keyurl string) (Settings, error) {
	priv, err := key.GetEdDSAPrivateKey()
	if err != nil {
		return Settings{}, err
	}
	if len(priv) == ed25519.SeedSize {
		return Settings{Ed25519, ed25519.NewKeyFromSeed(priv), [144]byte{0x00}, key.GetKeyID(), keyurl}, nil
	}
	if len(priv) == 144 {
		var arr [144]byte
		copy(arr[:], priv)
		return Settings{Ed448, nil, arr, key.GetKeyID(), keyurl}, nil
	}
	return Settings{}, errors.New("private key has wrong size")
}

// AddPublicKey adds a public key for verification
func (p *Provider) AddPublicKey(key jwk.JWK) error {
	id := key.GetKeyID()
	enc, err := key.GetEdDSAPublicKey()
	if err != nil {
		return err
	}
	if key.Crv == jwk.CurveEd448 {
		if _, ok := p.c4[id]; ok {
			return errors.New("key ID already exists")
		}
		var pub [56]byte
		copy(pub[:], enc)
		p.c4[id] = pub
		return nil
	}
	if _, ok := p.c2[id]; ok {
		return errors.New("key ID already exists")
	}
	p.c2[id] = ed25519.PublicKey(enc)
	return nil
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
func (p Provider) CurrentKey() jwk.JWK {
	if p.curve == Ed25519 {
		key, _ := jwk.NewEdDSAPublicKey(p.c2[p.settings.kid], p.settings.kid)
		return key
	}
	if p.curve == Ed448 {
		k := p.c4[p.settings.kid]
		key, _ := jwk.NewEdDSAPublicKey(k[:], p.settings.kid)
		return key
	}
	return jwk.JWK{}
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
