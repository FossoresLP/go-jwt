package jwk

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

func NewRSAPublicKey(key *rsa.PublicKey, keyID string) JWK {
	n := key.N.Bytes()
	e := big.NewInt(int64(key.E)).Bytes()
	nb := base64.URLEncoding.EncodeToString(n)
	eb := base64.URLEncoding.EncodeToString(e)
	return JWK{Kty: KeyTypeRSA, N: nb, E: eb, Kid: keyID}
}

func (k JWK) GetRSAPublicKey() (*rsa.PublicKey, error) {
	if k.Kty != KeyTypeRSA {
		return nil, fmt.Errorf("Key type %q cannot be converted to RSA public key", k.Kty)
	}
	nb, err := base64.URLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.URLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	n := &big.Int{}
	n.SetBytes(nb)
	e := &big.Int{}
	e.SetBytes(eb)
	eint := int(e.Int64())
	return &rsa.PublicKey{N: n, E: eint}, nil
}

func NewRSAPrivateKey(key *rsa.PrivateKey, keyID string) JWK {
	return JWK{
		Kty: KeyTypeRSA,
		N:   base64.URLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.URLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		D:   base64.URLEncoding.EncodeToString(key.D.Bytes()),
		P:   base64.URLEncoding.EncodeToString(key.Primes[0].Bytes()),
		Q:   base64.URLEncoding.EncodeToString(key.Primes[1].Bytes()),
		Dp:  base64.URLEncoding.EncodeToString(key.Precomputed.Dp.Bytes()),
		Dq:  base64.URLEncoding.EncodeToString(key.Precomputed.Dq.Bytes()),
		Qi:  base64.URLEncoding.EncodeToString(key.Precomputed.Qinv.Bytes()),
		Kid: keyID,
	}
}

func (k JWK) GetRSAPrivateKey() (*rsa.PrivateKey, error) {
	if k.Kty != KeyTypeRSA {
		return nil, fmt.Errorf("Key type %q cannot be converted to RSA public key", k.Kty)
	}
	nb, err := base64.URLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.URLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	db, err := base64.URLEncoding.DecodeString(k.D)
	if err != nil {
		return nil, err
	}
	pb, err := base64.URLEncoding.DecodeString(k.P)
	if err != nil {
		return nil, err
	}
	qb, err := base64.URLEncoding.DecodeString(k.Q)
	if err != nil {
		return nil, err
	}
	dpb, err := base64.URLEncoding.DecodeString(k.Dp)
	if err != nil {
		return nil, err
	}
	dqb, err := base64.URLEncoding.DecodeString(k.Dq)
	if err != nil {
		return nil, err
	}
	qib, err := base64.URLEncoding.DecodeString(k.Qi)
	if err != nil {
		return nil, err
	}
	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: (&big.Int{}).SetBytes(nb),
			E: int((&big.Int{}).SetBytes(eb).Int64()),
		},
		D: (&big.Int{}).SetBytes(db),
		Primes: []*big.Int{
			(&big.Int{}).SetBytes(pb),
			(&big.Int{}).SetBytes(qb),
		},
		Precomputed: rsa.PrecomputedValues{
			Dp:        (&big.Int{}).SetBytes(dpb),
			Dq:        (&big.Int{}).SetBytes(dqb),
			Qinv:      (&big.Int{}).SetBytes(qib),
			CRTValues: []rsa.CRTValue{},
		},
	}, nil
}
