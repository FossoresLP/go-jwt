package rs

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"

	"github.com/fossoreslp/go-jwt"
	"github.com/fossoreslp/go-uuid-v4"
)

const (
	// RS256 is RSA PKCS#1 v1.5 using SHA256
	RS256 = "RS256"

	// RS384 is RSA PKCS#1 v1.5 using SHA384
	RS384 = "RS384"

	// RS512 is RSA PKCS#1 v1.5 using SHA512
	RS512 = "RS512"
)

// Provider is an interface all providers in this package support
type Provider interface {
	Header(h *jwt.Header)
	Sign(c []byte) []byte
	Verify(data, sig []byte, h jwt.Header) bool
}

// NewProvider creates a new Provider generating the necessary keypairs
func NewProvider(t string) (Provider, []PublicKey, error) {
	return NewProviderWithKeyURL(t, "")
}

// NewProviderWithKeyURL works just like NewProvider but also sets the key URL of the generated keys
func NewProviderWithKeyURL(t, keyURL string) (Provider, []PublicKey, error) {
	kid, err := uuid.NewString()
	if err != nil {
		return nil, nil, err
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	var p Provider
	switch t {
	case RS256:
		p = RS256Provider{k, &k.PublicKey, kid, keyURL, true, true}
	case RS384:
		p = RS384Provider{k, &k.PublicKey, kid, keyURL, true, true}
	case RS512:
		p = RS512Provider{k, &k.PublicKey, kid, keyURL, true, true}
	default:
		return nil, nil, errors.New("type string invalid")
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return p, []PublicKey{PublicKey{pub, kid}}, nil
}

// LoadProvider returns a Provider using the supplied keypairs
func LoadProvider(k KeySet, t string) Provider {
	switch t {
	case RS256:
		return RS256Provider(k)
	case RS384:
		return RS384Provider(k)
	case RS512:
		return RS512Provider(k)
	}
	return nil
}

// RS256Provider provides RSA PKCS#1 v1.5 using SHA256 JWS signing and verification
type RS256Provider KeySet

// Header sets the necessary JWT header fields
func (p RS256Provider) Header(h *jwt.Header) {
	h.Alg = RS256
	KeySet(p).header(h)
}

// Sign signs the content of a JWT
func (p RS256Provider) Sign(c []byte) []byte {
	hash := sha256.Sum256(c)
	return KeySet(p).sign(crypto.SHA256, hash[:])
}

// Verify verifies if the content matches it's signature.
func (p RS256Provider) Verify(data, sig []byte, h jwt.Header) bool {
	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(p.public, crypto.SHA256, hash[:], sig) == nil
}

// RS384Provider provides RSA PKCS#1 v1.5 using SHA384 JWS signing and verification
type RS384Provider KeySet

// Header sets the necessary JWT header fields
func (p RS384Provider) Header(h *jwt.Header) {
	h.Alg = RS384
	KeySet(p).header(h)
}

// Sign signs the content of a JWT
func (p RS384Provider) Sign(c []byte) []byte {
	hash := sha512.Sum384(c)
	return KeySet(p).sign(crypto.SHA384, hash[:])
}

// Verify verifies if the content matches it's signature.
func (p RS384Provider) Verify(data, sig []byte, h jwt.Header) bool {
	hash := sha512.Sum384(data)
	return rsa.VerifyPKCS1v15(p.public, crypto.SHA384, hash[:], sig) == nil
}

// RS512Provider provides RSA PKCS#1 v1.5 using SHA512 JWS signing and verification
type RS512Provider KeySet

// Header sets the necessary JWT header fields
func (p RS512Provider) Header(h *jwt.Header) {
	h.Alg = RS512
	KeySet(p).header(h)
}

// Sign signs the content of a JWT
func (p RS512Provider) Sign(c []byte) []byte {
	hash := sha512.Sum512(c)
	return KeySet(p).sign(crypto.SHA512, hash[:])
}

// Verify verifies if the content matches it's signature.
func (p RS512Provider) Verify(data, sig []byte, h jwt.Header) bool {
	hash := sha512.Sum512(data)
	return rsa.VerifyPKCS1v15(p.public, crypto.SHA512, hash[:], sig) == nil
}
