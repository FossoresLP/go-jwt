package es

import (
	"encoding/pem"
	"testing"

	"github.com/fossoreslp/go-jwt"
)

func TestES256(t *testing.T) {
	p, err := NewProvider(ES256)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	rk := p.CurrentKey()
	b := pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: rk.GetPublicKey()}
	t.Logf("Created provider with key: %s", string(pem.EncodeToMemory(&b)))
	jwt.SetSignatureProvider(algToString(ES256), p)
	jwt.SetSigningAlgorithm(algToString(ES256)) // nolint:errcheck
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
	if !dec.Valid() {
		t.Errorf("Decoded JWT could not be validated: %s", dec.ValidationError().Error())
	}
}

func TestES384(t *testing.T) {
	p, err := NewProvider(ES384)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	rk := p.CurrentKey()
	b := pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: rk.GetPublicKey()}
	t.Logf("Created provider with key: %s", string(pem.EncodeToMemory(&b)))
	jwt.SetSignatureProvider(algToString(ES384), p)
	jwt.SetSigningAlgorithm(algToString(ES384)) // nolint:errcheck
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
	if !dec.Valid() {
		t.Errorf("Decoded JWT could not be validated: %s", dec.ValidationError().Error())
	}
}

func TestES512(t *testing.T) {
	p, err := NewProvider(ES512)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	rk := p.CurrentKey()
	b := pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: rk.GetPublicKey()}
	t.Logf("Created provider with key: %s", string(pem.EncodeToMemory(&b)))
	jwt.SetSignatureProvider(algToString(ES512), p)
	jwt.SetSigningAlgorithm(algToString(ES512)) // nolint:errcheck
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
	if !dec.Valid() {
		t.Errorf("Decoded JWT could not be validated: %s", dec.ValidationError().Error())
	}
}
