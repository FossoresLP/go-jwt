package ps

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
	// PS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256
	PS256 = 1

	// PS384 is RSASSA-PSS using SHA-384 and MGF1 with SHA-384
	PS384 = 2

	// PS512 is RSASSA-PSS using SHA-512 and MGF1 with SHA-512
	PS512 = 3
)

func algToString(alg int) string {
	switch alg {
	case PS256:
		return "PS256"
	case PS384:
		return "PS384"
	case PS512:
		return "PS512"
	default:
		return ""
	}
}

// init is only here to make sure the imports for SHA256, SHA384 and SHA512 are not removed automatically and the are therefore available to hash.Hash
func init() {
	_ = sha256.New()
	_ = sha512.New()
}

var (
	ps256opts = &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}
	ps384opts = &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384}
	ps512opts = &rsa.PSSOptions{SaltLength: 64, Hash: crypto.SHA512}
)

// Provider provides RSASSA-PSS using SHA2 and MGF1 with SHA2 JWS signing and verification
type Provider struct {
	alg      int
	pssopts  *rsa.PSSOptions
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
	case PS256:
		return Provider{PS256, ps256opts, Settings{k, kid, keyURL}, m}, nil
	case PS384:
		return Provider{PS384, ps384opts, Settings{k, kid, keyURL}, m}, nil
	case PS512:
		return Provider{PS512, ps512opts, Settings{k, kid, keyURL}, m}, nil
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
	case PS256:
		return Provider{PS256, ps256opts, s, m}, nil
	case PS384:
		return Provider{PS384, ps384opts, s, m}, nil
	case PS512:
		return Provider{PS512, ps512opts, s, m}, nil
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
	hash := p.pssopts.Hash.New()
	// SHA2 does not return errors
	hash.Write(c) // nolint:errcheck
	sum, err := rsa.SignPSS(rand.Reader, p.settings.private, p.pssopts.Hash, hash.Sum(nil), p.pssopts)
	if err != nil {
		return nil, err
	}
	return sum, nil
}

// Verify verifies if the content matches it's signature.
func (p Provider) Verify(data, sig []byte, h jwt.Header) error {
	hash := p.pssopts.Hash.New()
	// SHA2 does not return errors
	hash.Write(data) // nolint:errcheck
	pub, ok := p.keys[h.Kid]
	if !ok {
		return errors.New("unknown key id")
	}
	if rsa.VerifyPSS(pub, p.pssopts.Hash, hash.Sum(nil), sig, p.pssopts) == nil {
		return nil
	}
	return errors.New("signature invalid")
}
