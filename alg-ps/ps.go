package ps

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"

	"github.com/fossoreslp/go-jwt"
	"github.com/fossoreslp/go-jwt/publickey"
	"github.com/fossoreslp/go-uuid-v4"
)

const (
	// PS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256
	PS256 = "PS256"

	// PS384 is RSASSA-PSS using SHA-384 and MGF1 with SHA-384
	PS384 = "PS384"

	// PS512 is RSASSA-PSS using SHA-512 and MGF1 with SHA-512
	PS512 = "PS512"
)

// init is only here to make sure the imports for SHA256, SHA384 and SHA512 are not removed automatically and the are therefore available to hash.Hash
func init() {
	_ = sha256.New()
	_ = sha512.New()
}

// Provider provides RSASSA-PSS using SHA2 and MGF1 with SHA2 JWS signing and verification
type Provider struct {
	alg     string
	pssopts *rsa.PSSOptions
	set     KeySet
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
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Provider{}, nil, err
	}
	var p Provider
	switch t {
	case PS256:
		p = Provider{PS256, &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}, KeySet{k, &k.PublicKey, kid, keyURL, true, true}}
	case PS384:
		p = Provider{PS384, &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384}, KeySet{k, &k.PublicKey, kid, keyURL, true, true}}
	case PS512:
		p = Provider{PS512, &rsa.PSSOptions{SaltLength: 64, Hash: crypto.SHA512}, KeySet{k, &k.PublicKey, kid, keyURL, true, true}}
	default:
		return Provider{}, nil, errors.New("type string invalid")
	}
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey) // Marshaling a generated RSA public key should never fail - ignoring error
	return p, []publickey.PublicKey{publickey.New(pub, kid)}, nil
}

// LoadProvider returns a Provider using the supplied keypairs
func LoadProvider(k KeySet, t string) Provider {
	switch t {
	case PS256:
		return Provider{PS256, &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}, k}
	case PS384:
		return Provider{PS384, &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384}, k}
	case PS512:
		return Provider{PS512, &rsa.PSSOptions{SaltLength: 64, Hash: crypto.SHA512}, k}
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
	hash := p.pssopts.Hash.New()
	hash.Write(c)
	sum, err := rsa.SignPSS(rand.Reader, p.set.private, p.pssopts.Hash, hash.Sum(nil), p.pssopts)
	if err != nil {
		return nil
	}
	return sum
}

// Verify verifies if the content matches it's signature.
func (p Provider) Verify(data, sig []byte, h jwt.Header) bool {
	if !p.set.canVerify {
		return false
	}
	hash := p.pssopts.Hash.New()
	hash.Write(data)
	return rsa.VerifyPSS(p.set.public, p.pssopts.Hash, hash.Sum(nil), sig, p.pssopts) == nil
}
