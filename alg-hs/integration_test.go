package hs

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/fossoreslp/go-jwt"
)

func TestHS256(t *testing.T) {
	p, err := NewProvider(HS256)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	rk := p.CurrentKey()
	bk := make([]byte, base64.StdEncoding.EncodedLen(len(rk.GetPublicKey())))
	base64.StdEncoding.Encode(bk, rk.GetPublicKey())
	t.Logf("Created provider with key: %s", string(bk))
	jwt.SetAlgorithm(algToString(HS256), p)
	jwt.SetSigningAlgorithm(algToString(HS256)) // nolint:errcheck
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

func TestHS384(t *testing.T) {
	p, err := NewProvider(HS384)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	rk := p.CurrentKey()
	bk := make([]byte, base64.StdEncoding.EncodedLen(len(rk.GetPublicKey())))
	base64.StdEncoding.Encode(bk, rk.GetPublicKey())
	t.Logf("Created provider with key: %s", string(bk))
	jwt.SetAlgorithm(algToString(HS384), p)
	jwt.SetSigningAlgorithm(algToString(HS384)) // nolint:errcheck
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

func TestHS512(t *testing.T) {
	p, err := NewProvider(HS512)
	if err != nil {
		t.Errorf("Could not initialize provider: %s", err.Error())
	}
	rk := p.CurrentKey()
	bk := make([]byte, base64.StdEncoding.EncodedLen(len(rk.GetPublicKey())))
	base64.StdEncoding.Encode(bk, rk.GetPublicKey())
	t.Logf("Created provider with key: %s", string(bk))
	jwt.SetAlgorithm(algToString(HS512), p)
	jwt.SetSigningAlgorithm(algToString(HS512)) // nolint:errcheck
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

func TestHeader(t *testing.T) {
	h := jwt.Header{Typ: "JWT"}
	Provider{alg: HS256, settings: Settings{kid: "key_id", jku: "key_url"}}.Header(&h)
	if h.Alg != "HS256" {
		t.Errorf("HS256Provider.Header() should set Alg to \"HS256\" but instead it is %q", h.Alg)
	}
	if h.Kid != "key_id" {
		t.Errorf("HS256Provider.Header() should set Kid to \"key_id\" but instead it is %q", h.Kid)
	}
	if h.Jku != "key_url" {
		t.Errorf("HS256Provider.Header() should set Jku to \"key_url\" but instead it is %q", h.Jku)
	}

	h = jwt.Header{Typ: "JWT"}
	Provider{alg: HS384, settings: Settings{kid: "key_id", jku: "key_url"}}.Header(&h)
	if h.Alg != "HS384" {
		t.Errorf("HS384Provider.Header() should set Alg to \"HS384\" but instead it is %q", h.Alg)
	}
	if h.Kid != "key_id" {
		t.Errorf("HS384Provider.Header() should set Kid to \"key_id\" but instead it is %q", h.Kid)
	}
	if h.Jku != "key_url" {
		t.Errorf("HS384Provider.Header() should set Jku to \"key_url\" but instead it is %q", h.Jku)
	}

	h = jwt.Header{Typ: "JWT"}
	Provider{alg: HS512, settings: Settings{kid: "key_id", jku: "key_url"}}.Header(&h)
	if h.Alg != "HS512" {
		t.Errorf("HS512Provider.Header() should set Alg to \"HS512\" but instead it is %q", h.Alg)
	}
	if h.Kid != "key_id" {
		t.Errorf("HS512Provider.Header() should set Kid to \"key_id\" but instead it is %q", h.Kid)
	}
	if h.Jku != "key_url" {
		t.Errorf("HS512Provider.Header() should set Jku to \"key_url\" but instead it is %q", h.Jku)
	}

}

func TestLoadProvider(t *testing.T) {
	k, _ := LoadProvider(Settings{kid: "key_id"}, HS256)
	if k.alg != HS256 {
		t.Errorf("LoadProvider() did not return a HS256 provider but %d", k.alg)
	}
	if k.settings.kid != "key_id" {
		t.Errorf("LoadProvider() did not pass the data from the input keyset onto the provider")
	}

	k, _ = LoadProvider(Settings{kid: "key_id"}, HS384)
	if k.alg != HS384 {
		t.Errorf("LoadProvider() did not return a HS384 provider but %d", k.alg)
	}
	if k.settings.kid != "key_id" {
		t.Errorf("LoadProvider() did not pass the data from the input keyset onto the provider")
	}

	k, _ = LoadProvider(Settings{kid: "key_id"}, HS512)
	if k.alg != HS512 {
		t.Errorf("LoadProvider() did not return a HS512 provider but %d", k.alg)
	}
	if k.settings.kid != "key_id" {
		t.Errorf("LoadProvider() did not pass the data from the input keyset onto the provider")
	}
}

func TestUnknownAlgorithm(t *testing.T) {
	if _, err := NewProvider(12); err == nil {
		t.Error("NewProvider() with an unknown algorithm type should fail but returned no error.")
	}

	if _, err := LoadProvider(Settings{}, 12); err == nil {
		t.Error("LoadProvider() with an unknown algorithm type did not return an error.")
	}
}

func TestInvalidRandomGenerator(t *testing.T) {
	random := rand.Reader
	rand.Reader = bytes.NewReader(nil)
	if _, err := NewProviderWithKeyURL(HS256, "key_url"); err == nil {
		t.Error("NewProviderWithKeyURL() should fail with invalid random generator for UUID")
	}
	b := [16]byte{0x00}
	rand.Reader = bytes.NewReader(b[:])
	if _, err := NewProviderWithKeyURL(HS256, "key_url"); err == nil {
		t.Error("NewProviderWithKeyURL() should fail with empty random generator for secret key")
	}
	rand.Reader = random
}

func TestInvalidSignature(t *testing.T) {
	p := Provider{hmac: hmac.New(sha256.New, []byte("key"))}
	if p.Verify([]byte("test"), []byte("signature"), jwt.Header{}) == nil {
		t.Error("Provider.Verify() should fail with invalid signature")
	}
}
