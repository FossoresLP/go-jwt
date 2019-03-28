package ps

import (
	"encoding/pem"
	"testing"

	"github.com/fossoreslp/go-jwt"
	"github.com/fossoreslp/go-jwt/publickey"
)

func TestPS256(t *testing.T) {
	p, err := NewProvider(PS256)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	rk := p.CurrentKey().GetPublicKey()
	b := pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: rk}
	t.Logf("Created provider with key: %s", string(pem.EncodeToMemory(&b)))
	jwt.SetAlgorithm("PS256", p)
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
	rk := p.CurrentKey().GetPublicKey()
	b := pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: rk}
	t.Logf("Created provider with key: %s", string(pem.EncodeToMemory(&b)))
	jwt.SetAlgorithm("PS384", p)
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
	rk := p.CurrentKey().GetPublicKey()
	b := pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: rk}
	t.Logf("Created provider with key: %s", string(pem.EncodeToMemory(&b)))
	jwt.SetAlgorithm("PS512", p)
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

func TestVerify(t *testing.T) {
	token := []byte("eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.oywIg-I6w59yw9jiPxewn5n2BhrD7hSifWSmzFKGBMPEMd0qweVNjlyxu2TodunPzlh49OW8QA0ygNRL9VQrWA3GXzb5FubNF4s7Y15QePx52anlvebzihx5-hR0UhKbVC0UODwYNMiY-v0L7iMbT9UvuSj0GAuZMxndo2Y2VFQ")
	pemKey := []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D
o2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----`)
	key, _ := pem.Decode(pemKey)
	if key == nil {
		t.Errorf("Key could not be read")
	}
	settings, err := NewSettings(pkcs1, "key_id")
	if err != nil {
		t.Errorf("Could not decode key: %s", err.Error())
		t.FailNow()
	}
	p, _ := LoadProvider(settings, PS384)
	p.RemovePublicKey("")
	err = p.AddPublicKey(publickey.New(key.Bytes, ""))
	if err != nil {
		t.Errorf("Could not add public key: %s", err.Error())
	}
	jwt.SetAlgorithm("PS384", p)
	jwt.SetSigningAlgorithm("PS384") // nolint:errcheck
	dec, err := jwt.Decode(token)
	if err != nil {
		t.Errorf("Could not decode JWT: %s", err.Error())
	}
	if !dec.Valid() {
		t.Errorf("Decoded JWT could not be validated: %s", dec.ValidationError().Error())
	}
}
