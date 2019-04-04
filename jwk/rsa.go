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
	n := key.N.Bytes()
	e := big.NewInt(int64(key.E)).Bytes()
	d := key.D.Bytes()
	p := key.Primes[0].Bytes()
	q := key.Primes[1].Bytes()
	dp := key.Precomputed.Dp.Bytes()
	dq := key.Precomputed.Dq.Bytes()
	qi := key.Precomputed.Qinv.Bytes()
	nb := base64.URLEncoding.EncodeToString(n)
	eb := base64.URLEncoding.EncodeToString(e)
	db := base64.URLEncoding.EncodeToString(d)
	pb := base64.URLEncoding.EncodeToString(p)
	qb := base64.URLEncoding.EncodeToString(q)
	dpb := base64.URLEncoding.EncodeToString(dp)
	dqb := base64.URLEncoding.EncodeToString(dq)
	qib := base64.URLEncoding.EncodeToString(qi)
	return JWK{Kty: KeyTypeRSA, N: nb, E: eb, D: db, P: pb, Q: qb, Dp: dpb, Dq: dqb, Qi: qib, Kid: keyID}
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
	n := &big.Int{}
	n.SetBytes(nb)
	e := &big.Int{}
	e.SetBytes(eb)
	eint := int(e.Int64())
	d := &big.Int{}
	d.SetBytes(db)
	p := &big.Int{}
	p.SetBytes(pb)
	q := &big.Int{}
	q.SetBytes(qb)
	dp := &big.Int{}
	dp.SetBytes(dpb)
	dq := &big.Int{}
	dq.SetBytes(dqb)
	qi := &big.Int{}
	qi.SetBytes(qib)
	return &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: eint}, D: d, Primes: []*big.Int{p, q}, Precomputed: rsa.PrecomputedValues{Dp: dp, Dq: dq, Qinv: qi}}, nil
}
