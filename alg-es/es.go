package es

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"

	"github.com/fossoreslp/go-jwt"
	"github.com/fossoreslp/go-jwt/publickey"
	"github.com/fossoreslp/go-uuid-v4"
)

type curve struct {
	alg   string
	curve elliptic.Curve
	hash  crypto.Hash
	ilen  int
}

const (
	// ES256 is ECDSA using P-256 and SHA-256
	ES256 = "ES256"

	// ES384 is ECDSA using P-384 and SHA-384
	ES384 = "ES384"

	// ES512 is ECDSA using P-521 and SHA-512
	ES512 = "ES512"
)

var (
	c256 = curve{ES256, elliptic.P256(), crypto.SHA256, 32}
	c384 = curve{ES384, elliptic.P384(), crypto.SHA384, 48}
	c521 = curve{ES512, elliptic.P521(), crypto.SHA512, 66}
)

// init is only here to make sure the imports for SHA256, SHA384 and SHA512 are not removed automatically and the are therefore available to hash.Hash
func init() {
	_ = sha256.New()
	_ = sha512.New()
}

// Provider provides ECDSA using the NIST curves and SHA2 for JWS signing and verification
type Provider struct {
	alg  string
	hash crypto.Hash
	set  KeySet
	ilen int
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
	var c curve
	switch t {
	case ES256:
		c = c256
	case ES384:
		c = c384
	case ES512:
		c = c521
	default:
		return Provider{}, nil, errors.New("type string invalid")
	}
	key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
	if err != nil {
		return Provider{}, nil, err
	}
	p := Provider{c.alg, c.hash, KeySet{key, &key.PublicKey, kid, keyURL, true, true}, c.ilen}
	return p, []publickey.PublicKey{publickey.New(p.set.GetPublicKey().GetPublicKey(), kid)}, nil
}

// LoadProvider returns a Provider using the supplied keypairs
func LoadProvider(k KeySet, t string) Provider {
	switch t {
	case ES256:
		return Provider{ES256, crypto.SHA256, k, 32}
	case ES384:
		return Provider{ES384, crypto.SHA384, k, 48}
	case ES512:
		return Provider{ES512, crypto.SHA512, k, 66}
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
	if !p.set.canSign {
		return nil
	}
	hash := p.hash.New()
	hash.Write(c)
	r, s, err := ecdsa.Sign(rand.Reader, p.set.private, hash.Sum(nil))
	if err != nil {
		return nil
	}

	rb := r.Bytes()
	sb := s.Bytes()

	if len(rb) > p.ilen {
		rb = rb[len(rb)-p.ilen:]
	}
	if len(sb) > p.ilen {
		sb = sb[len(sb)-p.ilen:]
	}

	if len(rb) < p.ilen {
		p := make([]byte, p.ilen-len(rb))
		rb = append(p, rb...)
	}
	if len(sb) < p.ilen {
		p := make([]byte, p.ilen-len(sb))
		sb = append(p, sb...)
	}

	return append(rb, sb...)
}

// Verify verifies if the content matches it's signature.
func (p Provider) Verify(data, sig []byte, h jwt.Header) bool {
	if !p.set.canVerify {
		println("!canVerify")
		return false
	}
	if len(sig) != 2*p.ilen {
		println("len(sig) != 64")
		return false
	}
	hash := p.hash.New()
	hash.Write(data)
	r := big.Int{}
	s := big.Int{}
	r.SetBytes(sig[:p.ilen])
	s.SetBytes(sig[p.ilen:])
	return ecdsa.Verify(p.set.public, hash.Sum(nil), &r, &s)
}
