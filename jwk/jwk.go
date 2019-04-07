package jwk

import (
	"encoding/base64"
	"fmt"
)

// JWK represents a JSON Web Key used for verifying JSON Web Signatures.
type JWK struct {
	// Key type
	Kty KeyType `json:"kty"`
	// Curve (EC / OKP)
	Crv Curve `json:"crv,omitempty"`
	// Public
	X string `json:"x,omitempty"` // EC / OKP
	Y string `json:"y,omitempty"` // EC
	N string `json:"n,omitempty"` // RSA
	E string `json:"e,omitempty"` // RSA
	//Private
	D  string `json:"d,omitempty"`  // RSA / EC / OKP
	P  string `json:"p,omitempty"`  // RSA
	Q  string `json:"q,omitempty"`  // RSA
	Dp string `json:"dp,omitempty"` // RSA
	Dq string `json:"dq,omitempty"` // RSA
	Qi string `json:"qi,omitempty"` // RSA
	K  string `json:"k,omitempty"`  // Symmetric / Other
	// Key use
	Use Use `json:"use,omitempty"`
	// Key operations
	KeyOps []KeyOperation `json:"key_ops,omitempty"`
	// Algorithm the key is intended for
	Alg Algorithm `json:"alg,omitempty"`
	// Key ID
	Kid string `json:"kid,omitempty"`
}

// GetKeyID returns the key ID
func (k JWK) GetKeyID() string {
	return k.Kid
}

// NewBasic converts a symmetric / other key to a JWK
func NewBasic(key []byte, keyID string) JWK {
	kb := base64.URLEncoding.EncodeToString(key)
	return JWK{Kty: KeyTypeOct, K: kb, Kid: keyID}
}

// GetBasic tries to convert a JWK to a symmetric / other key and returns an error in case that's not possible
func (k JWK) GetBasic() ([]byte, error) {
	if k.Kty != KeyTypeOct {
		return nil, fmt.Errorf("Key type %q cannot be converted to symmetric key", k.Kty)
	}
	key, err := base64.URLEncoding.DecodeString(k.K)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Set is a set of JSON Web Keys with an added issuer key
type Set struct {
	Keys      []JWK  `json:"keys"`
	Signature []byte `json:"jwk-signature.fossores.de"`
}
