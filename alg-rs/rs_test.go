package rs

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"reflect"
	"testing"

	"github.com/fossoreslp/go-jwt"
)

func TestNewProviderWithKeyURL(t *testing.T) {
	// Save default rand.Reader
	random := rand.Reader
	// Failure to generate UUID
	rand.Reader = bytes.NewReader(nil)
	_, err := NewProviderWithKeyURL(RS256, "")
	if err == nil {
		t.Error("NewProviderWithKeyURL() should fail when no key ID could be generated but did not")
	}

	// Failure to generate key
	b16 := [16]byte{0x00}
	rand.Reader = bytes.NewReader(b16[:])
	_, err = NewProviderWithKeyURL(RS256, "")
	if err == nil {
		t.Error("NewProviderWithKeyURL() should fail when no key could be generated but did not")
	}
	// Restore default rand.Reader
	rand.Reader = random

	// Invalid type string
	_, err = NewProviderWithKeyURL(12, "")
	if err == nil {
		t.Error("NewProviderWithKeyURL() should fail with unknown algorithm type but did not")
	}
}

func TestLoadProvider(t *testing.T) {
	m := map[string]*rsa.PublicKey{
		"": &pub,
	}
	type args struct {
		s Settings
		t int
	}
	tests := []struct {
		name    string
		args    args
		want    Provider
		wantErr bool
	}{
		{"RS256", args{Settings{private: priv}, RS256}, Provider{RS256, crypto.SHA256, Settings{private: priv}, m}, false},
		{"RS384", args{Settings{private: priv}, RS384}, Provider{RS384, crypto.SHA384, Settings{private: priv}, m}, false},
		{"RS512", args{Settings{private: priv}, RS512}, Provider{RS512, crypto.SHA512, Settings{private: priv}, m}, false},
		{"Unknown type", args{Settings{private: priv}, 12}, Provider{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadProvider(tt.args.s, tt.args.t)
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
	pAlg := Provider{alg: RS256}
	pAlg.Header(&h)
	if h.Alg != "RS256" {
		t.Errorf("Provider.Header() should set Alg to \"RS256\" but is %q", h.Alg)
	}
	pKid := Provider{settings: Settings{kid: "key_id"}}
	pKid.Header(&h)
	if h.Kid != "key_id" {
		t.Errorf("Provider.Header() should set Kid to \"key_id\" but is %q", h.Kid)
	}
	pJku := Provider{settings: Settings{jku: "key_url"}}
	pJku.Header(&h)
	if h.Jku != "key_url" {
		t.Errorf("Provider.Header() should set Jku to \"key_url\" but is %q", h.Jku)
	}
}

func TestProvider_Sign(t *testing.T) {

	// Save default rand.Reader
	random := rand.Reader

	// No random data available
	priv := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(3603479687), E: 65537}, D: big.NewInt(674849825), Primes: []*big.Int{big.NewInt(64063), big.NewInt(56249)}, Precomputed: rsa.PrecomputedValues{Dp: big.NewInt(20717), Dq: big.NewInt(42569), Qinv: big.NewInt(7600), CRTValues: []rsa.CRTValue{}}}
	rand.Reader = bytes.NewReader(nil)
	p := Provider{hash: crypto.SHA256, settings: Settings{private: priv}}
	if _, err := p.Sign(nil); err == nil {
		t.Error("Sign() did not return an error when no random data was available to generate signature")
	}

	// Restore default rand.Reader
	rand.Reader = random
}

func TestProvider_Verify(t *testing.T) {
	p := Provider{hash: crypto.SHA256, keys: map[string]*rsa.PublicKey{"key_id": &rsa.PublicKey{N: big.NewInt(3603479687), E: 65537}}}
	if p.Verify(nil, nil, jwt.Header{}) == nil {
		t.Error("Verify() did not return an error when encountering an unknown key ID")
	}
	if p.Verify([]byte("test"), []byte("signature"), jwt.Header{Kid: "key_id"}) == nil {
		t.Error("Verify() did not return an error when encountering an invalid signature")
	}
}
