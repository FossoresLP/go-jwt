package hs

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"

	"github.com/fossoreslp/go-jwt"
	"github.com/fossoreslp/go-uuid-v4"
)

const (
	// HS256 is HMAC-SHA256
	HS256 = 1

	// HS384 is HMAC-SHA384
	HS384 = 2

	// HS512 is HMAC-SHA512
	HS512 = 3
)

func algToString(alg int) string {
	switch alg {
	case HS256:
		return "HS256"
	case HS384:
		return "HS384"
	case HS512:
		return "HS512"
	default:
		return ""
	}
}

// Provider provides HMAC-SHA2 JWS signing and verification
type Provider struct {
	alg      int
	hmac     hash.Hash
	settings Settings
	keys     map[string][]byte
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
	var c int
	var alg int
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
		return Provider{}, errors.New("invalid algorithm ID")
	}
	k := make([]byte, c)
	_, err = rand.Read(k)
	if err != nil {
		return Provider{}, err
	}
	m := map[string][]byte{
		kid: k,
		"":  k,
	}
	return Provider{alg, hmac.New(h, k), Settings{k, kid, keyURL}, m}, nil
}

// LoadProvider returns a Provider using the supplied keypairs
func LoadProvider(s Settings, t int) (Provider, error) {
	m := map[string][]byte{
		s.kid: s.key,
		"":    s.key,
	}
	switch t {
	case HS256:
		return Provider{HS256, hmac.New(sha256.New, s.key), s, m}, nil
	case HS384:
		return Provider{HS384, hmac.New(sha512.New384, s.key), s, m}, nil
	case HS512:
		return Provider{HS512, hmac.New(sha512.New, s.key), s, m}, nil
	}
	return Provider{}, errors.New("invalid algorithm ID")
}

func getMAC(mac hash.Hash, in []byte) []byte {
	mac.Reset()
	// HMAC only returns the error of SHA2 which itself does not return an error
	mac.Write(in) // nolint:errcheck
	return mac.Sum(nil)
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
	return getMAC(p.hmac, c), nil
}

// Verify verifies if the content matches it's signature.
func (p Provider) Verify(data, sig []byte, h jwt.Header) error {
	var hashFunc func() hash.Hash
	switch h.Alg {
	case "HS256":
		hashFunc = sha256.New
	case "HS384":
		hashFunc = sha512.New384
	case "HS512":
		hashFunc = sha512.New
	default:
		return errors.New("invalid algorithm")
	}
	pub, ok := p.keys[h.Kid]
	if !ok {
		return errors.New("unknown key id")
	}
	expectedMAC := getMAC(hmac.New(hashFunc, pub), data)
	if hmac.Equal(sig, expectedMAC) {
		return nil
	}
	return errors.New("signature invalid")
}
