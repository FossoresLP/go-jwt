package es

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/fossoreslp/go-jwt"
)

func TestNewProviderWithKeyURL(t *testing.T) {
	// Save default rand.Reader
	random := rand.Reader
	// Failure to generate UUID
	rand.Reader = bytes.NewReader(nil)
	_, _, err := NewProviderWithKeyURL(ES256, "")
	if err == nil {
		t.Error("NewProviderWithKeyURL() should fail when no key ID could be generated but did not")
	}

	// Failure to generate key
	b16 := [16]byte{0x00}
	rand.Reader = bytes.NewReader(b16[:])
	_, _, err = NewProviderWithKeyURL(ES256, "")
	if err == nil {
		t.Error("NewProviderWithKeyURL() should fail when no key could be generated but did not")
	}
	// Restore default rand.Reader
	rand.Reader = random

	// Invalid type string
	_, _, err = NewProviderWithKeyURL("unknown", "")
	if err == nil {
		t.Error("NewProviderWithKeyURL() should fail with unknown algorithm type but did not")
	}
}

func TestLoadProvider(t *testing.T) {
	type args struct {
		k KeySet
		t string
	}
	tests := []struct {
		name    string
		args    args
		want    Provider
		wantErr bool
	}{
		{"RS256", args{KeySet{}, ES256}, Provider{ES256, crypto.SHA256, KeySet{}, 32}, false},
		{"RS384", args{KeySet{}, ES384}, Provider{ES384, crypto.SHA384, KeySet{}, 48}, false},
		{"RS512", args{KeySet{}, ES512}, Provider{ES512, crypto.SHA512, KeySet{}, 66}, false},
		{"Unknown type", args{KeySet{}, "unknown"}, Provider{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadProvider(tt.args.k, tt.args.t)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadProvider() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProvider_Header(t *testing.T) {
	h := jwt.Header{Typ: "JWT"}
	pAlg := Provider{alg: ES256}
	pAlg.Header(&h)
	if h.Alg != ES256 {
		t.Errorf("Provider.Header() should set Alg to \"ES256\" but is %q", h.Alg)
	}
	pKid := Provider{set: KeySet{kid: "key_id"}}
	pKid.Header(&h)
	if h.Kid != "key_id" {
		t.Errorf("Provider.Header() should set Kid to \"key_id\" but is %q", h.Kid)
	}
	pJku := Provider{set: KeySet{jku: "key_url"}}
	pJku.Header(&h)
	if h.Jku != "key_url" {
		t.Errorf("Provider.Header() should set Jku to \"key_url\" but is %q", h.Jku)
	}
}

func TestProvider_Sign(t *testing.T) {
	// CanSign == false
	p := Provider{set: KeySet{canSign: false}}
	if _, err := p.Sign(nil); err == nil {
		t.Error("Sign() did not return an error when canSign is false")
	}

	// Save default rand.Reader
	random := rand.Reader

	// No random data available
	priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	rand.Reader = bytes.NewReader(nil)
	p = Provider{hash: crypto.SHA256, set: KeySet{private: priv, canSign: true}, ilen: 16}
	if _, err := p.Sign(nil); err == nil {
		t.Error("Sign() did not return an error when no random data was available to generate signature")
	}

	// Restore default rand.Reader
	rand.Reader = random

	// Test truncation
	b, _ := p.Sign(nil)
	if l := len(b); l != 32 {
		t.Errorf("Sign() should return byte slice of length 32 but was %d", l)
	}

	// Test length extension
	p.ilen = 128
	b, _ = p.Sign(nil)
	if l := len(b); l != 256 {
		t.Errorf("Sign() should return byte slice of length 256 but was %d", l)
	}
}

func TestProvider_Verify(t *testing.T) {
	p := Provider{set: KeySet{canVerify: false}}
	if p.Verify(nil, nil, jwt.Header{}) == nil {
		t.Error("Verify() did not return an error when canVerify is false")
	}
	p = Provider{hash: crypto.SHA256, set: KeySet{public: &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, canVerify: true}, ilen: 32}
	b := [12]byte{0xFF}
	if p.Verify(nil, b[:], jwt.Header{}) == nil {
		t.Error("Verify() did not return an error when signature has wrong length")
	}
	b2 := [64]byte{0xFF}
	if p.Verify([]byte("test"), b2[:], jwt.Header{}) == nil {
		t.Error("Verify() did not return an error when encountering a wrong signature")
	}
}
