package eddsa

import (
	"github.com/fossoreslp/go-jwt"
	"github.com/fossoreslp/go-jwt/publickey"
	"github.com/fossoreslp/go-uuid-v4"
	"github.com/otrv4/ed448"
	"golang.org/x/crypto/ed25519"
)

const (
	// Ed25519 is a twisted Edwards curve designed by Daniel J. Bernstein et. al. with a 126-bit security level
	Ed25519 = "Ed25519"
	// Ed448 is am Edwards curve designed by Mike Hamburg with a 223-bit security level
	Ed448 = "Ed448"
)

// Provider is a struct that stores all necessary data to sign and verify EdDSA signatures
type Provider struct {
	ed25519keyset Ed25519KeySet
	ed448keyset   Ed448KeySet
	ed448curve    ed448.Curve
	defaultCurve  string
}

// NewProvider creates a new Provider generating the necessary keypairs
func NewProvider(defaultCurve string) (Provider, []publickey.PublicKey, error) {
	pub2, priv2, err := ed25519.GenerateKey(nil)
	if err != nil {
		return Provider{}, nil, err
	}
	id2, err := uuid.NewString()
	if err != nil {
		return Provider{}, nil, err
	}
	ks2 := Ed25519KeySet{priv2, pub2, id2, "", true, true}
	curve := ed448.NewCurve()
	priv4, pub4, ok := curve.GenerateKeys()
	if !ok {
		return Provider{}, nil, err
	}
	id4, err := uuid.NewString()
	if err != nil {
		return Provider{}, nil, err
	}
	ks4 := Ed448KeySet{priv4, pub4, id4, "", true, true}
	return Provider{ks2, ks4, curve, defaultCurve}, []publickey.PublicKey{ks2.GetPublicKey(), ks4.GetPublicKey()}, nil
}

// NewProviderWithKeyURL works just like NewProvider but also sets the key URL of the generated keys
func NewProviderWithKeyURL(defaultCurve, keyURL string) (Provider, []publickey.PublicKey, error) {
	p, k, err := NewProvider(defaultCurve)
	if err != nil {
		return Provider{}, nil, err
	}
	p.ed25519keyset.SetKeyURL(keyURL)
	p.ed448keyset.SetKeyURL(keyURL)
	return p, k, nil
}

// LoadProvider returns a Provider using the supplied keypairs
func LoadProvider(k2 Ed25519KeySet, k4 Ed448KeySet, defaultCurve string) Provider {
	c := ed448.NewCurve()
	return Provider{k2, k4, c, defaultCurve}
}

// Header sets the necessary JWT header fields for the default curve
func (p Provider) Header(h *jwt.Header) {
	h.Alg = "EdDSA"
	h.Crv = p.defaultCurve
	switch p.defaultCurve {
	case Ed25519:
		if p.ed25519keyset.kid != "" {
			h.Kid = p.ed25519keyset.kid
		}
		if p.ed25519keyset.jku != "" {
			h.Jku = p.ed25519keyset.jku
		}
	case Ed448:
		if p.ed448keyset.kid != "" {
			h.Kid = p.ed448keyset.kid
		}
		if p.ed448keyset.jku != "" {
			h.Jku = p.ed448keyset.jku
		}
	}
}

// Sign signs the content of a JWT using the default curve
func (p Provider) Sign(c []byte) []byte {
	switch p.defaultCurve {
	case Ed25519:
		if !p.ed25519keyset.canSign {
			return nil
		}
		return ed25519.Sign(p.ed25519keyset.private, c)
	case Ed448:
		if !p.ed448keyset.canSign {
			return nil
		}
		sig, ok := p.ed448curve.Sign(p.ed448keyset.private, c)
		if !ok {
			return nil
		}
		return sig[:]
	}
	return nil
}

// Verify verifies if the content matches it's signature. The curve to use is set by the header.
func (p Provider) Verify(data, sig []byte, h jwt.Header) bool {
	switch h.Crv {
	case Ed25519:
		if !p.ed25519keyset.canVerify {
			return false
		}
		return ed25519.Verify(p.ed25519keyset.public, data, sig)
	case Ed448:
		if !p.ed448keyset.canVerify {
			return false
		}
		var signature [112]byte
		copy(signature[:], sig)
		return p.ed448curve.Verify(signature, data, p.ed448keyset.public)
	}
	return false
}
