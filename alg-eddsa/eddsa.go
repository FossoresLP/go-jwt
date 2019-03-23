package eddsa

import (
	"errors"

	"github.com/fossoreslp/go-jwt"
	"github.com/fossoreslp/go-jwt/publickey"
	"github.com/otrv4/ed448"
	"golang.org/x/crypto/ed25519"
)

const (
	// Ed25519 is a twisted Edwards curve designed by Daniel J. Bernstein et. al. with a 126-bit security level.
	Ed25519 = 1
	// Ed448 is am Edwards curve designed by Mike Hamburg with a 223-bit security level. It's implementation in Go is currently not stable so use with care.
	Ed448 = 2
)

// Provider is a struct that stores all necessary data to sign and verify EdDSA signatures
type Provider struct {
	settings Settings                     // Signature settings
	c2       map[string]ed25519.PublicKey // Ed25519 key collection
	c4       map[string][56]byte          // Ed448 key collection
	curve    int                          // Curve curve
}

// NewProvider creates a new Provider generating the necessary keypairs
func NewProvider(alg int) (Provider, error) {
	return NewProviderWithKeyURL(alg, "")
}

// NewProviderWithKeyURL works just like NewProvider but also sets the key URL of the generated keys
func NewProviderWithKeyURL(alg int, keyURL string) (Provider, error) {
	if alg == Ed25519 {
		priv, pub, id, err := generateEd25519Keys()
		if err != nil {
			return Provider{}, err
		}
		m := map[string]ed25519.PublicKey{
			id: pub,
			"": pub,
		}
		return Provider{Settings{Ed25519, priv, [144]byte{0x0}, id, keyURL}, m, make(map[string][56]byte), alg}, nil
	}
	if alg == Ed448 {
		priv, pub, id, err := generateEd448Keys()
		if err != nil {
			return Provider{}, err
		}
		m := map[string][56]byte{
			id: pub,
			"": pub,
		}
		return Provider{Settings{Ed448, nil, priv, id, keyURL}, make(map[string]ed25519.PublicKey), m, alg}, nil
	}
	return Provider{}, errors.New("invalid algorithm ID")
}

// LoadProvider returns a Provider using the supplied keypairs
func LoadProvider(settings Settings, public publickey.PublicKey, alg int) (Provider, error) {
	if alg == Ed25519 {
		if settings.typ != Ed25519 {
			return Provider{}, errors.New("signature settings are not for Ed25519")
		}
		id := public.GetKeyID()
		enc := public.GetPublicKey()
		if len(enc) != ed25519.PublicKeySize {
			return Provider{}, errors.New("public key is not for Ed25519")
		}
		m := map[string]ed25519.PublicKey{
			id: ed25519.PublicKey(enc),
			"": ed25519.PublicKey(enc),
		}
		return Provider{settings, m, make(map[string][56]byte), alg}, nil
	}
	if alg == Ed448 {
		if settings.typ != Ed448 {
			return Provider{}, errors.New("signature settings are not for Ed448")
		}
		id := public.GetKeyID()
		enc := public.GetPublicKey()
		if len(enc) != 56 {
			return Provider{}, errors.New("public key is not for Ed448")
		}
		var dec [56]byte
		copy(dec[:], enc)
		m := map[string][56]byte{
			id: dec,
			"": dec,
		}
		return Provider{settings, make(map[string]ed25519.PublicKey), m, alg}, nil
	}
	return Provider{}, errors.New("invalid algorithm ID")
}

// Header sets the necessary JWT header fields for the default curve
func (p Provider) Header(h *jwt.Header) {
	h.Alg = "EdDSA"
	switch p.curve {
	case Ed25519:
		h.Crv = "Ed25519"
	case Ed448:
		h.Crv = "Ed448"
	}
	if p.settings.kid != "" {
		h.Kid = p.settings.kid
	}
	if p.settings.jku != "" {
		h.Jku = p.settings.jku
	}
}

// Sign signs the content of a JWT using the default curve
func (p Provider) Sign(c []byte) ([]byte, error) {
	switch p.curve {
	case Ed25519:
		return ed25519.Sign(p.settings.ed25519, c), nil
	case Ed448:
		sig, ok := ed448.NewCurve().Sign(p.settings.ed448, c)
		if !ok {
			return nil, errors.New("signing failed")
		}
		return sig[:], nil
	}
	return nil, errors.New("unknown curve")
}

// Verify verifies if the content matches it's signature. The curve to use is set by the header.
func (p Provider) Verify(data, sig []byte, h jwt.Header) error {
	switch h.Crv {
	case "Ed25519":
		pub, ok := p.c2[h.Kid]
		if !ok {
			return errors.New("unknown key id")
		}
		if ed25519.Verify(pub, data, sig) {
			return nil
		}
		return errors.New("signature invalid")
	case "Ed448":
		pub, ok := p.c4[h.Kid]
		if !ok {
			return errors.New("unknown key id")
		}
		var signature [112]byte
		copy(signature[:], sig)
		if ed448.NewCurve().Verify(signature, data, pub) {
			return nil
		}
		return errors.New("signature invalid")
	}
	return errors.New("unknown curve")
}
