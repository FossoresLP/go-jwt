package hs

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"reflect"
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

func TestHeader(t *testing.T) {
	h := jwt.Header{Typ: "JWT"}
	Provider{alg: HS256, set: KeySet{kid: "key_id", jku: "key_url"}}.Header(&h)
	if h.Alg != HS256 {
		t.Errorf("HS256Provider.Header() should set Alg to \"HS256\" but instead it is %q", h.Alg)
	}
	if h.Kid != "key_id" {
		t.Errorf("HS256Provider.Header() should set Kid to \"key_id\" but instead it is %q", h.Kid)
	}
	if h.Jku != "key_url" {
		t.Errorf("HS256Provider.Header() should set Jku to \"key_url\" but instead it is %q", h.Jku)
	}

	h = jwt.Header{Typ: "JWT"}
	Provider{alg: HS384, set: KeySet{kid: "key_id", jku: "key_url"}}.Header(&h)
	if h.Alg != HS384 {
		t.Errorf("HS384Provider.Header() should set Alg to \"HS384\" but instead it is %q", h.Alg)
	}
	if h.Kid != "key_id" {
		t.Errorf("HS384Provider.Header() should set Kid to \"key_id\" but instead it is %q", h.Kid)
	}
	if h.Jku != "key_url" {
		t.Errorf("HS384Provider.Header() should set Jku to \"key_url\" but instead it is %q", h.Jku)
	}

	h = jwt.Header{Typ: "JWT"}
	Provider{alg: HS512, set: KeySet{kid: "key_id", jku: "key_url"}}.Header(&h)
	if h.Alg != HS512 {
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
	k := LoadProvider(KeySet{kid: "key_id"}, HS256)
	if k.alg != HS256 {
		t.Errorf("LoadProvider() did not return a HS256 provider but %s", k.alg)
	}
	if k.set.kid != "key_id" {
		t.Errorf("LoadProvider() did not pass the data from the input keyset onto the provider")
	}

	k = LoadProvider(KeySet{kid: "key_id"}, HS384)
	if k.alg != HS384 {
		t.Errorf("LoadProvider() did not return a HS384 provider but %s", k.alg)
	}
	if k.set.kid != "key_id" {
		t.Errorf("LoadProvider() did not pass the data from the input keyset onto the provider")
	}

	k = LoadProvider(KeySet{kid: "key_id"}, HS512)
	if k.alg != HS512 {
		t.Errorf("LoadProvider() did not return a HS512 provider but %s", k.alg)
	}
	if k.set.kid != "key_id" {
		t.Errorf("LoadProvider() did not pass the data from the input keyset onto the provider")
	}
}

func TestUnknownAlgorithm(t *testing.T) {
	if _, _, err := NewProvider("unknown"); err == nil {
		t.Error("NewProvider() with an unknown algorithm type should fail but returned no error.")
	}

	if !reflect.DeepEqual(LoadProvider(KeySet{}, "unknown"), Provider{}) {
		t.Error("LoadProvider() with an unknown algorithm type did not return nil.")
	}
}

func TestInvalidRandomGenerator(t *testing.T) {
	random := rand.Reader
	rand.Reader = bytes.NewReader(nil)
	if _, _, err := NewProviderWithKeyURL(HS256, "key_url"); err == nil {
		t.Error("NewProviderWithKeyURL() should fail with invalid random generator for UUID")
	}
	b := [16]byte{0x00}
	rand.Reader = bytes.NewReader(b[:])
	if _, _, err := NewProviderWithKeyURL(HS256, "key_url"); err == nil {
		t.Error("NewProviderWithKeyURL() should fail with empty random generator for secret key")
	}
	rand.Reader = random
}
