package ps

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
	_, _, err := NewProviderWithKeyURL(PS256, "")
	if err == nil {
		t.Error("NewProviderWithKeyURL() should fail when no key ID could be generated but did not")
	}

	// Failure to generate key
	b16 := [16]byte{0x00}
	rand.Reader = bytes.NewReader(b16[:])
	_, _, err = NewProviderWithKeyURL(PS256, "")
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
		name string
		args args
		want Provider
	}{
		{"PS256", args{KeySet{}, PS256}, Provider{PS256, &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}, KeySet{}}},
		{"PS384", args{KeySet{}, PS384}, Provider{PS384, &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384}, KeySet{}}},
		{"PS512", args{KeySet{}, PS512}, Provider{PS512, &rsa.PSSOptions{SaltLength: 64, Hash: crypto.SHA512}, KeySet{}}},
		{"Unknown type", args{KeySet{}, "unknown"}, Provider{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LoadProvider(tt.args.k, tt.args.t); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadProvider() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProvider_Header(t *testing.T) {
	h := jwt.Header{Typ: "JWT"}
	pAlg := Provider{alg: PS256}
	pAlg.Header(&h)
	if h.Alg != PS256 {
		t.Errorf("Provider.Header() should set Alg to \"RS256\" but is %q", h.Alg)
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
	priv := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(3603479687), E: 65537}, D: big.NewInt(674849825), Primes: []*big.Int{big.NewInt(64063), big.NewInt(56249)}, Precomputed: rsa.PrecomputedValues{Dp: big.NewInt(20717), Dq: big.NewInt(42569), Qinv: big.NewInt(7600), CRTValues: []rsa.CRTValue{}}}
	rand.Reader = bytes.NewReader(nil)
	p = Provider{pssopts: &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}, set: KeySet{private: priv, canSign: true}}
	if _, err := p.Sign(nil); err == nil {
		t.Error("Sign() did not return an error when no random data was available to generate signature")
	}

	// Restore default rand.Reader
	rand.Reader = random
}

func TestProvider_Verify(t *testing.T) {
	p := Provider{set: KeySet{canVerify: false}}
	if p.Verify(nil, nil, jwt.Header{}) == nil {
		t.Error("Verify() did not return an error when canVerify is false")
	}
}
