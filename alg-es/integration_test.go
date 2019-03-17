package es

import (
	"encoding/pem"
	"testing"

	"github.com/fossoreslp/go-jwt"
)

func TestES256(t *testing.T) {
	p, k, err := NewProvider(ES256)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	rk := k[0].GetPublicKey()
	b := pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: rk}
	t.Logf("Created provider with key: %s", string(pem.EncodeToMemory(&b)))
	jwt.SetAlgorithm(ES256, p)
	jwt.DefaultAlgorithm(ES256)
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

func TestES384(t *testing.T) {
	p, k, err := NewProvider(ES384)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	rk := k[0].GetPublicKey()
	b := pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: rk}
	t.Logf("Created provider with key: %s", string(pem.EncodeToMemory(&b)))
	jwt.SetAlgorithm(ES384, p)
	jwt.DefaultAlgorithm(ES384)
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

func TestES512(t *testing.T) {
	p, k, err := NewProvider(ES512)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	rk := k[0].GetPublicKey()
	b := pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: rk}
	t.Logf("Created provider with key: %s", string(pem.EncodeToMemory(&b)))
	jwt.SetAlgorithm(ES512, p)
	jwt.DefaultAlgorithm(ES512)
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
