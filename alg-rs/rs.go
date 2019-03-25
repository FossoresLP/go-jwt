package rs

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"

	"github.com/fossoreslp/go-jwt"
	"github.com/fossoreslp/go-uuid-v4"
)

const (
	// RS256 is RSA PKCS#1 v1.5 using SHA256
	RS256 = 1

	// RS384 is RSA PKCS#1 v1.5 using SHA384
	RS384 = 2

	// RS512 is RSA PKCS#1 v1.5 using SHA512
	RS512 = 3
)

func algToString(alg int) string {
	switch alg {
	case RS256:
		return "RS256"
	case RS384:
		return "RS384"
	case RS512:
		return "RS512"
	default:
		return ""
	}
}

// init is only here to make sure the imports for SHA256, SHA384 and SHA512 are not removed automatically and the are therefore available to hash.Hash
func init() {
	_ = sha256.New()
	_ = sha512.New()
}

// Provider provides RSA PKCS#1 v1.5 using the selected hashing algorithm JWS signing and verification
type Provider struct {
	alg      int
	hash     crypto.Hash
	settings Settings
	keys     map[string]*rsa.PublicKey
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
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Provider{}, err
	}
	m := map[string]*rsa.PublicKey{
		kid: &k.PublicKey,
		"":  &k.PublicKey,
	}
	switch t {
	case RS256:
		return Provider{RS256, crypto.SHA256, Settings{k, kid, keyURL}, m}, nil
	case RS384:
		return Provider{RS384, crypto.SHA384, Settings{k, kid, keyURL}, m}, nil
	case RS512:
		return Provider{RS512, crypto.SHA512, Settings{k, kid, keyURL}, m}, nil
	default:
		return Provider{}, errors.New("type string invalid")
	}
}

// LoadProvider returns a Provider using the supplied keypairs
func LoadProvider(s Settings, t int) (Provider, error) {
	m := map[string]*rsa.PublicKey{
		s.kid: &s.private.PublicKey,
		"":    &s.private.PublicKey,
	}
	switch t {
	case RS256:
		return Provider{RS256, crypto.SHA256, s, m}, nil
	case RS384:
		return Provider{RS384, crypto.SHA384, s, m}, nil
	case RS512:
		return Provider{RS512, crypto.SHA512, s, m}, nil
	}
	return Provider{}, errors.New("type string invalid")
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
	sum, err := rsa.SignPKCS1v15(rand.Reader, p.settings.private, p.hash, hash.Sum(nil))
	if err != nil {
		return nil, err
	}
	return sum, nil
}

// Verify verifies if the content matches it's signature.
func (p Provider) Verify(data, sig []byte, h jwt.Header) error {
	hash := p.hash.New()
	// SHA2 does not return errors
	hash.Write(data) // nolint:errcheck
	pub, ok := p.keys[h.Kid]
	if !ok {
		return errors.New("unknown key id")
	}
	if rsa.VerifyPKCS1v15(pub, p.hash, hash.Sum(nil), sig) == nil {
		return nil
	}
	return errors.New("signature invalid")
}
