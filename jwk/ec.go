package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
)

func NewECPublicKey(key *ecdsa.PublicKey, keyID string) (JWK, error) {
	var curve Curve
	switch key.Curve.Params().Name {
	case "P-256":
		curve = CurveP256
	case "P-384":
		curve = CurveP384
	case "P-521":
		curve = CurveP521
	default:
		return JWK{}, fmt.Errorf("Unknown curve %q", key.Curve.Params().Name)
	}
	numBytes := key.Curve.Params().BitSize / 8
	if key.Curve.Params().BitSize%8 != 0 {
		numBytes++
	}
	x := key.X.Bytes()
	y := key.Y.Bytes()
	if len(x) < numBytes {
		pad := make([]byte, numBytes-len(x))
		x = append(pad, x...)
	}
	if len(y) < numBytes {
		pad := make([]byte, numBytes-len(y))
		y = append(pad, y...)
	}
	xb := base64.URLEncoding.EncodeToString(x)
	yb := base64.URLEncoding.EncodeToString(y)
	return JWK{Kty: KeyTypeEC, Crv: curve, X: xb, Y: yb, Kid: keyID}, nil
}

func (k JWK) GetECPublicKey() (*ecdsa.PublicKey, error) {
	if k.Kty != KeyTypeEC {
		return nil, fmt.Errorf("Key type %q cannot be converted to EC public key", k.Kty)
	}
	var curve elliptic.Curve
	switch k.Crv {
	case CurveP256:
		curve = elliptic.P256()
	case CurveP384:
		curve = elliptic.P384()
	case CurveP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("Unknown curve %q", k.Crv)
	}
	xb, err := base64.URLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yb, err := base64.URLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	numBytes := curve.Params().BitSize / 8
	if curve.Params().BitSize%8 != 0 {
		numBytes++
	}
	if len(xb) != numBytes {
		return nil, fmt.Errorf("Got %d bytes for X but want %d", len(xb), numBytes)
	}
	if len(yb) != numBytes {
		return nil, fmt.Errorf("Got %d bytes for Y but want %d", len(yb), numBytes)
	}
	x := &big.Int{}
	x.SetBytes(xb)
	y := &big.Int{}
	y.SetBytes(yb)
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func NewECPrivateKey(key *ecdsa.PrivateKey, keyID string) (JWK, error) {
	var curve Curve
	switch key.Curve.Params().Name {
	case "P-256":
		curve = CurveP256
	case "P-384":
		curve = CurveP384
	case "P-521":
		curve = CurveP521
	default:
		return JWK{}, fmt.Errorf("Unknown curve %q", key.Curve.Params().Name)
	}
	numBytes := key.Curve.Params().BitSize / 8
	if key.Curve.Params().BitSize%8 != 0 {
		numBytes++
	}
	x := key.X.Bytes()
	y := key.Y.Bytes()
	d := key.D.Bytes()
	if len(x) < numBytes {
		pad := make([]byte, numBytes-len(x))
		x = append(pad, x...)
	}
	if len(y) < numBytes {
		pad := make([]byte, numBytes-len(y))
		y = append(pad, y...)
	}
	xb := base64.URLEncoding.EncodeToString(x)
	yb := base64.URLEncoding.EncodeToString(y)
	db := base64.URLEncoding.EncodeToString(d)
	return JWK{Kty: KeyTypeEC, Crv: curve, X: xb, Y: yb, D: db, Kid: keyID}, nil
}

func (k JWK) GetECPrivateKey() (*ecdsa.PrivateKey, error) {
	if k.Kty != KeyTypeEC {
		return nil, fmt.Errorf("Key type %q cannot be converted to EC public key", k.Kty)
	}
	var curve elliptic.Curve
	switch k.Crv {
	case CurveP256:
		curve = elliptic.P256()
	case CurveP384:
		curve = elliptic.P384()
	case CurveP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("Unknown curve %q", k.Crv)
	}
	xb, err := base64.URLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yb, err := base64.URLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	db, err := base64.URLEncoding.DecodeString(k.D)
	if err != nil {
		return nil, err
	}
	numBytes := curve.Params().BitSize / 8
	if curve.Params().BitSize%8 != 0 {
		numBytes++
	}
	if len(xb) != numBytes {
		return nil, fmt.Errorf("Got %d bytes for X but want %d", len(xb), numBytes)
	}
	if len(yb) != numBytes {
		return nil, fmt.Errorf("Got %d bytes for Y but want %d", len(yb), numBytes)
	}
	x := &big.Int{}
	x.SetBytes(xb)
	y := &big.Int{}
	y.SetBytes(yb)
	d := &big.Int{}
	d.SetBytes(db)
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}, nil
}
