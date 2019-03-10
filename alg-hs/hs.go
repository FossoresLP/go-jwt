package hs

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"

	"github.com/fossoreslp/go-jwt"
	"github.com/fossoreslp/go-jwt/publickey"
	"github.com/fossoreslp/go-uuid-v4"
)

const (
	// HS256 is HMAC-SHA256
	HS256 = "HS256"

	// HS384 is HMAC-SHA384
	HS384 = "HS384"

	// HS512 is HMAC-SHA512
	HS512 = "HS512"
)

// Provider is an interface all providers in this package support
type Provider interface {
	Header(h *jwt.Header)
	Sign(c []byte) []byte
	Verify(data, sig []byte, h jwt.Header) bool
}

// NewProvider creates a new Provider generating the necessary keypairs
func NewProvider(t string) (Provider, []publickey.PublicKey, error) {
	return NewProviderWithKeyURL(t, "")
}

// NewProviderWithKeyURL works just like NewProvider but also sets the key URL of the generated keys
func NewProviderWithKeyURL(t, keyURL string) (Provider, []publickey.PublicKey, error) {
	kid, err := uuid.NewString()
	if err != nil {
		return nil, nil, err
	}
	var c int
	switch t {
	case HS256:
		c = 32
	case HS384:
		c = 48
	case HS512:
		c = 64
	default:
		return nil, nil, errors.New("type string is invalid")
	}
	b := make([]byte, c)
	_, err = rand.Read(b)
	if err != nil {
		return nil, nil, err
	}
	var p Provider
	switch t {
	case HS256:
		p = HS256Provider{b, kid, keyURL}
	case HS384:
		p = HS384Provider{b, kid, keyURL}
	case HS512:
		p = HS512Provider{b, kid, keyURL}
	}
	return p, []publickey.PublicKey{publickey.New(b, kid)}, nil
}

// LoadProvider returns a Provider using the supplied keypairs
func LoadProvider(k KeySet, t string) Provider {
	switch t {
	case HS256:
		return HS256Provider(k)
	case HS384:
		return HS384Provider(k)
	case HS512:
		return HS512Provider(k)
	}
	return nil
}

// HS256Provider provides HMAC-SHA256 JWS signing and verification
type HS256Provider KeySet

// Header sets the necessary JWT header fields
func (p HS256Provider) Header(h *jwt.Header) {
	h.Alg = HS256
	if p.kid != "" {
		h.Kid = p.kid
	}
	if p.jku != "" {
		h.Jku = p.jku
	}
}

// Sign signs the content of a JWT
func (p HS256Provider) Sign(c []byte) []byte {
	mac := hmac.New(sha256.New, p.key)
	mac.Write(c)
	return mac.Sum(nil)
}

// Verify verifies if the content matches it's signature.
func (p HS256Provider) Verify(data, sig []byte, h jwt.Header) bool {
	mac := hmac.New(sha256.New, p.key)
	mac.Write(data)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(sig, expectedMAC)
}

// HS384Provider provides HMAC-SHA384 JWS signing and verification
type HS384Provider KeySet

// Header sets the necessary JWT header fields
func (p HS384Provider) Header(h *jwt.Header) {
	h.Alg = HS384
	if p.kid != "" {
		h.Kid = p.kid
	}
	if p.jku != "" {
		h.Jku = p.jku
	}
}

// Sign signs the content of a JWT
func (p HS384Provider) Sign(c []byte) []byte {
	mac := hmac.New(sha512.New384, p.key)
	mac.Write(c)
	return mac.Sum(nil)
}

// Verify verifies if the content matches it's signature.
func (p HS384Provider) Verify(data, sig []byte, h jwt.Header) bool {
	mac := hmac.New(sha512.New384, p.key)
	mac.Write(data)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(sig, expectedMAC)
}

// HS512Provider provides HMAC-SHA512 JWS signing and verification
type HS512Provider KeySet

// Header sets the necessary JWT header fields
func (p HS512Provider) Header(h *jwt.Header) {
	h.Alg = HS512
	if p.kid != "" {
		h.Kid = p.kid
	}
	if p.jku != "" {
		h.Jku = p.jku
	}
}

// Sign signs the content of a JWT
func (p HS512Provider) Sign(c []byte) []byte {
	mac := hmac.New(sha512.New, p.key)
	mac.Write(c)
	return mac.Sum(nil)
}

// Verify verifies if the content matches it's signature.
func (p HS512Provider) Verify(data, sig []byte, h jwt.Header) bool {
	mac := hmac.New(sha512.New, p.key)
	mac.Write(data)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(sig, expectedMAC)
}
