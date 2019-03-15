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

// init is only here to make sure the imports for SHA256, SHA384 and SHA512 are not removed automatically and therefore available to hash.Hash
func init() {
	_ = sha256.New()
	_ = sha512.New()
}

// Provider provides RSA PKCS#1 v1.5 using the selected hashing algorithm JWS signing and verification
type Provider struct {
	alg  string
	hash crypto.Hash
	set  KeySet
}

// NewProvider creates a new Provider generating the necessary keypairs
func NewProvider(t string) (Provider, []PublicKey, error) {
	return NewProviderWithKeyURL(t, "")
}

// NewProviderWithKeyURL works just like NewProvider but also sets the key URL of the generated keys
func NewProviderWithKeyURL(t, keyURL string) (Provider, []PublicKey, error) {
	kid, err := uuid.NewString()
	if err != nil {
		return Provider{}, nil, err
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Provider{}, nil, err
	}
	var p Provider
	switch t {
	case RS256:
		p = Provider{RS256, crypto.SHA256, KeySet{k, &k.PublicKey, kid, keyURL, true, true}}
	case RS384:
		p = Provider{RS384, crypto.SHA384, KeySet{k, &k.PublicKey, kid, keyURL, true, true}}
	case RS512:
		p = Provider{RS512, crypto.SHA512, KeySet{k, &k.PublicKey, kid, keyURL, true, true}}
	default:
		return Provider{}, nil, errors.New("type string invalid")
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return Provider{}, nil, err
	}
	return p, []PublicKey{PublicKey{pub, kid}}, nil
}

// LoadProvider returns a Provider using the supplied keypairs
func LoadProvider(k KeySet, t string) Provider {
	switch t {
	case RS256:
		return Provider{RS256, crypto.SHA256, k}
	case RS384:
		return Provider{RS384, crypto.SHA384, k}
	case RS512:
		return Provider{RS512, crypto.SHA512, k}
	}
	return Provider{}
}

// Header sets the necessary JWT header fields
func (p Provider) Header(h *jwt.Header) {
	h.Alg = p.alg
	if p.set.kid != "" {
		h.Kid = p.set.kid
	}
	if p.set.jku != "" {
		h.Jku = p.set.jku
	}
}

// Sign signs the content of a JWT
func (p Provider) Sign(c []byte) []byte {
	hash := p.hash.New()
	hash.Write(c)
	sum, err := rsa.SignPKCS1v15(rand.Reader, p.set.private, p.hash, hash.Sum(nil))
	if err != nil {
		return nil
	}
	return sum
}

// Verify verifies if the content matches it's signature.
func (p Provider) Verify(data, sig []byte, h jwt.Header) bool {
	hash := p.hash.New()
	hash.Write(data)
	return rsa.VerifyPKCS1v15(p.set.public, p.hash, hash.Sum(nil), sig) == nil
}
