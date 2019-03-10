package hs

import (
	"encoding/base64"
	"testing"

	"github.com/fossoreslp/go-jwt"
)

func TestHS256(t *testing.T) {
	p, k, err := NewProvider(HS256)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	rk := k[0].GetPublicKey()
	bk := make([]byte, base64.StdEncoding.EncodedLen(len(rk)))
	base64.StdEncoding.Encode(bk, rk)
	t.Logf("Created provider with key: %s", string(bk))
	jwt.SetAlgorithm(HS256, p)
	jwt.DefaultAlgorithm(HS256)
	token := jwt.New([]byte(`{"test": 1}`))
	res, err := token.Encode()
	if err != nil {
		t.Errorf("Could not encode JWT: %s", err.Error())
	}
	t.Logf("JWT encoded to: %s", string(res))
	dec, err := jwt.Decode(res)
	if err != nil {
		t.Errorf("Could not decode JWT: %s", err.Error())
	}
	if dec.Valid() != nil {
		t.Errorf("Decoded JWT could not be validated: %s", dec.Valid().Error())
	}
}

func TestHS384(t *testing.T) {
	p, k, err := NewProvider(HS384)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	rk := k[0].GetPublicKey()
	bk := make([]byte, base64.StdEncoding.EncodedLen(len(rk)))
	base64.StdEncoding.Encode(bk, rk)
	t.Logf("Created provider with key: %s", string(bk))
	jwt.SetAlgorithm(HS384, p)
	jwt.DefaultAlgorithm(HS384)
	token := jwt.New([]byte(`{"test": 1}`))
	res, err := token.Encode()
	if err != nil {
		t.Errorf("Could not encode JWT: %s", err.Error())
	}
	t.Logf("JWT encoded to: %s", string(res))
	dec, err := jwt.Decode(res)
	if err != nil {
		t.Errorf("Could not decode JWT: %s", err.Error())
	}
	if dec.Valid() != nil {
		t.Errorf("Decoded JWT could not be validated: %s", dec.Valid().Error())
	}
}

func TestHS512(t *testing.T) {
	p, k, err := NewProvider(HS512)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	rk := k[0].GetPublicKey()
	bk := make([]byte, base64.StdEncoding.EncodedLen(len(rk)))
	base64.StdEncoding.Encode(bk, rk)
	t.Logf("Created provider with key: %s", string(bk))
	jwt.SetAlgorithm(HS512, p)
	jwt.DefaultAlgorithm(HS512)
	token := jwt.New([]byte(`{"test": 1}`))
	res, err := token.Encode()
	if err != nil {
		t.Errorf("Could not encode JWT: %s", err.Error())
	}
	t.Logf("JWT encoded to: %s", string(res))
	dec, err := jwt.Decode(res)
	if err != nil {
		t.Errorf("Could not decode JWT: %s", err.Error())
	}
	if dec.Valid() != nil {
		t.Errorf("Decoded JWT could not be validated: %s", dec.Valid().Error())
	}
}
