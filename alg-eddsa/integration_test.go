package eddsa

import (
	"testing"

	jwt "github.com/fossoreslp/go-jwt"
)

func TestEd25519(t *testing.T) {
	p, err := NewProvider(Ed25519)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	jwt.SetAlgorithm("EdDSA", p)
	jwt.SetSigningAlgorithm("EdDSA") // nolint:errcheck
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

func TestEd448(t *testing.T) {
	p, err := NewProvider(Ed448)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	jwt.SetAlgorithm("EdDSA", p)
	jwt.SetSigningAlgorithm("EdDSA") // nolint:errcheck
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
