package ps

import (
	"testing"

	"github.com/fossoreslp/go-jwt"
)

func TestPS256(t *testing.T) {
	p, err := NewProvider(PS256)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	jwt.SetSignatureProvider("PS256", p)
	jwt.SetSigningAlgorithm("PS256") // nolint:errcheck
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

func TestPS384(t *testing.T) {
	p, err := NewProvider(PS384)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	jwt.SetSignatureProvider("PS384", p)
	jwt.SetSigningAlgorithm("PS384") // nolint:errcheck
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

func TestPS512(t *testing.T) {
	p, err := NewProvider(PS512)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	jwt.SetSignatureProvider("PS512", p)
	jwt.SetSigningAlgorithm("PS512") // nolint:errcheck
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
