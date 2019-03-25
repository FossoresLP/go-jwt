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
	alg   int
	curve elliptic.Curve
	hash  crypto.Hash
	ilen  int
}

const (
	// ES256 is ECDSA using P-256 and SHA-256
	ES256 = 1

	// ES384 is ECDSA using P-384 and SHA-384
	ES384 = 2

	// ES512 is ECDSA using P-521 and SHA-512
	ES512 = 3
)

func algToString(alg int) string {
	switch alg {
	case ES256:
		return "ES256"
	case ES384:
		return "ES384"
	case ES512:
		return "ES512"
	default:
		return ""
	}
}

var (
	c256 = curve{ES256, elliptic.P256(), crypto.SHA256, 32}
	c384 = curve{ES384, elliptic.P384(), crypto.SHA384, 48}
	c521 = curve{ES512, elliptic.P521(), crypto.SHA512, 66}
)

// init is only here to make sure the imports for SHA256, SHA384 and SHA512 are not removed automatically and are therefore available to hash.Hash
func init() {
	_ = sha256.New()
	_ = sha512.New()
}

// Provider provides ECDSA using the NIST curves and SHA2 for JWS signing and verification
type Provider struct {
	alg      int
	hash     crypto.Hash
	settings Settings
	keys     map[string]*ecdsa.PublicKey
	ilen     int
}

// NewProvider creates a new Provider generating the necessary keypairs
func NewProvider(t int) (Provider, error) {
	return NewProviderWithKeyURL(t, "")
}

// NewProviderWithKeyURL works just like NewProvider but also sets the key URL of the generated keys
func NewProviderWithKeyURL(t int, keyURL string) (Provider, error) {
	kid, err := uuid.NewString()
	if err != nil {
		return Provider{}, err
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
		return Provider{}, errors.New("type invalid")
	}
	key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
	if err != nil {
		return Provider{}, err
	}
	m := map[string]*ecdsa.PublicKey{
		kid: &key.PublicKey,
		"":  &key.PublicKey,
	}
	return Provider{c.alg, c.hash, Settings{key, kid, keyURL}, m, c.ilen}, nil
}

// LoadProvider returns a Provider using the supplied settings.
// The public key will be ignored as the settings include all necessary information.
func LoadProvider(s Settings, _ publickey.PublicKey, t int) (Provider, error) {
	m := map[string]*ecdsa.PublicKey{
		s.kid: &s.private.PublicKey,
		"":    &s.private.PublicKey,
	}
	switch t {
	case ES256:
		return Provider{ES256, crypto.SHA256, s, m, 32}, nil
	case ES384:
		return Provider{ES384, crypto.SHA384, s, m, 48}, nil
	case ES512:
		return Provider{ES512, crypto.SHA512, s, m, 66}, nil
	}
	return Provider{}, errors.New("type invalid")
}

// Header sets the necessary JWT header fields
func (p Provider) Header(h *jwt.Header) {
	h.Alg = algToString(p.alg)
	if p.settings.kid != "" {
		h.Kid = p.settings.kid
	}
	if p.settings.jku != "" {
		h.Jku = p.settings.jku
	}
}

// Sign signs the content of a JWT
func (p Provider) Sign(c []byte) ([]byte, error) {
	hash := p.hash.New()
	// SHA2 does not return errors
	hash.Write(c) // nolint:errcheck
	r, s, err := ecdsa.Sign(rand.Reader, p.settings.private, hash.Sum(nil))
	if err != nil {
		return nil, err
	}

	rb := r.Bytes()
	sb := s.Bytes()

	// This should not be needed as no curve should return too many bytes but I'll leave it here because I'm not able to verify that behavior.
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

	return append(rb, sb...), nil
}

// Verify verifies if the content matches it's signature.
func (p Provider) Verify(data, sig []byte, h jwt.Header) error {
	if len(sig) != 2*p.ilen {
		return errors.New("signature invalid")
	}
	hash := p.hash.New()
	// SHA2 does not return errors
	hash.Write(data) // nolint:errcheck
	r := big.Int{}
	s := big.Int{}
	r.SetBytes(sig[:p.ilen])
	s.SetBytes(sig[p.ilen:])
	pub, ok := p.keys[h.Kid]
	if !ok {
		return errors.New("unknown key id")
	}
	if ecdsa.Verify(pub, hash.Sum(nil), &r, &s) {
		return nil
	}
	return errors.New("signature invalid")
}
