package hs

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"

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

// Provider provides HMAC-SHA2 JWS signing and verification
type Provider struct {
	alg  string
	hmac hash.Hash
	set  KeySet
}

// NewProvider creates a new Provider generating the necessary keypairs
func NewProvider(t string) (Provider, []publickey.PublicKey, error) {
	return NewProviderWithKeyURL(t, "")
}

// NewProviderWithKeyURL works just like NewProvider but also sets the key URL of the generated keys
func NewProviderWithKeyURL(t, keyURL string) (Provider, []publickey.PublicKey, error) {
	kid, err := uuid.NewString()
	if err != nil {
		return Provider{}, nil, err
	}
	var c int
	var alg string
	var h func() hash.Hash
	switch t {
	case HS256:
		c = 32
		alg = HS256
		h = sha256.New
	case HS384:
		c = 48
		alg = HS384
		h = sha512.New384
	case HS512:
		c = 64
		alg = HS512
		h = sha512.New
	default:
		return Provider{}, nil, errors.New("type string is invalid")
	}
	k := make([]byte, c)
	_, err = rand.Read(k)
	if err != nil {
		return Provider{}, nil, err
	}
	return Provider{alg, hmac.New(h, k), KeySet{k, kid, keyURL}}, []publickey.PublicKey{publickey.New(k, kid)}, nil
}

// LoadProvider returns a Provider using the supplied keypairs
func LoadProvider(k KeySet, t string) Provider {
	switch t {
	case HS256:
		return Provider{HS256, hmac.New(sha256.New, k.key), k}
	case HS384:
		return Provider{HS384, hmac.New(sha512.New384, k.key), k}
	case HS512:
		return Provider{HS512, hmac.New(sha512.New, k.key), k}
	}
	return Provider{}
}

func (p Provider) getMAC(in []byte) []byte {
	p.hmac.Reset()
	p.hmac.Write(in)
	return p.hmac.Sum(nil)
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
func (p Provider) Sign(c []byte) ([]byte, error) {
	return p.getMAC(c), nil
}

// Verify verifies if the content matches it's signature.
func (p Provider) Verify(data, sig []byte, h jwt.Header) bool {
	expectedMAC := p.getMAC(data)
	return hmac.Equal(sig, expectedMAC)
}
