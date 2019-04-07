package jwk

import (
	"encoding/base64"
	"fmt"
)

// NewEdDSAPublicKey converts an EdDSA public key to a JWK and returns an error in case that's not possible
func NewEdDSAPublicKey(key []byte, keyID string) (JWK, error) {
	var curve Curve
	switch len(key) {
	case 32:
		curve = CurveEd25519
	case 56:
		curve = CurveEd448
	default:
		return JWK{}, fmt.Errorf("No known curve matches key length %d", len(key))
	}
	xb := base64.URLEncoding.EncodeToString(key)
	return JWK{Kty: KeyTypeOKP, Crv: curve, X: xb, Kid: keyID}, nil
}

// GetEdDSAPublicKey tries to convert a JWK to a EdDSA public key and returns an error in case that's not possible
func (k JWK) GetEdDSAPublicKey() ([]byte, error) {
	if k.Kty != KeyTypeOKP {
		return nil, fmt.Errorf("Key type %q cannot be converted to EdDSA public key", k.Kty)
	}
	x, err := base64.URLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	if k.Crv == CurveEd25519 {
		if len(x) != 32 {
			return nil, fmt.Errorf("Length %d is invalid for Ed25519 public key, want 32", len(x))
		}
		return x, nil
	}
	if k.Crv == CurveEd448 {
		if len(x) != 56 {
			return nil, fmt.Errorf("Length %d is invalid for Ed448 public key, want 56", len(x))
		}
		return x, nil
	}
	return nil, fmt.Errorf("Unknown curve %q", k.Crv)
}

// NewEdDSAPrivateKey converts an EdDSA private key to a JWK and returns an error in case that's not possible
func NewEdDSAPrivateKey(key []byte, public []byte, keyID string) (JWK, error) {
	var curve Curve
	switch len(key) {
	case 32:
		curve = CurveEd25519
		if len(public) != 32 {
			return JWK{}, fmt.Errorf("Ed25519 public key should be 32 bytes but is %d", len(public))
		}
	case 144:
		curve = CurveEd448
		if len(public) != 56 {
			return JWK{}, fmt.Errorf("Ed25519 public key should be 56 bytes but is %d", len(public))
		}
	default:
		return JWK{}, fmt.Errorf("No known curve matches key length %d", len(key))
	}
	db := base64.URLEncoding.EncodeToString(key)
	xb := base64.URLEncoding.EncodeToString(public)
	return JWK{Kty: KeyTypeOKP, Crv: curve, X: xb, D: db, Kid: keyID}, nil
}

// GetEdDSAPrivateKey tries to convert a JWK to a EdDSA private key and returns an error in case that's not possible
func (k JWK) GetEdDSAPrivateKey() ([]byte, error) {
	if k.Kty != KeyTypeOKP {
		return nil, fmt.Errorf("Key type %q cannot be converted to EdDSA private key", k.Kty)
	}
	x, err := base64.URLEncoding.DecodeString(k.D)
	if err != nil {
		return nil, err
	}
	if k.Crv == CurveEd25519 {
		if len(x) != 32 {
			return nil, fmt.Errorf("Length %d is invalid for Ed25519 private key, want 32", len(x))
		}
		return x, nil
	}
	if k.Crv == CurveEd448 {
		if len(x) != 144 {
			return nil, fmt.Errorf("Length %d is invalid for Ed448 private key, want 144", len(x))
		}
		return x, nil
	}
	return nil, fmt.Errorf("Unknown curve %q", k.Crv)
}
