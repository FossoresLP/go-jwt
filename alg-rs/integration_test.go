package rs

import (
	"encoding/pem"
	"testing"

	"github.com/fossoreslp/go-jwt"
)

func TestRS256(t *testing.T) {
	p, k, err := NewProvider(RS256)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	b := pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: k[0].GetPublicKey()}
	t.Logf("Created provider with key: %s", string(pem.EncodeToMemory(&b)))
	jwt.SetAlgorithm(RS256, p)
	jwt.DefaultAlgorithm(RS256)
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

func TestRS384(t *testing.T) {
	p, k, err := NewProvider(RS384)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	b := pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: k[0].GetPublicKey()}
	t.Logf("Created provider with key: %s", string(pem.EncodeToMemory(&b)))
	jwt.SetAlgorithm(RS384, p)
	jwt.DefaultAlgorithm(RS384)
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

func TestRS512(t *testing.T) {
	p, k, err := NewProvider(RS512)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	b := pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: k[0].GetPublicKey()}
	t.Logf("Created provider with key: %s", string(pem.EncodeToMemory(&b)))
	jwt.SetAlgorithm(RS512, p)
	jwt.DefaultAlgorithm(RS512)
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
