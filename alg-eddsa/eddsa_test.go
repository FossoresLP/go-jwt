package eddsa

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/otrv4/ed448"

	"github.com/fossoreslp/go-jwt"
)

func TestNewProvider(t *testing.T) {
	p, k, err := NewProvider(Ed25519)
	if err != nil {
		t.Errorf("NewProvider() returned an error: %s", err.Error())
	}
	if p.defaultCurve != Ed25519 {
		t.Errorf("NewProvider() failed to set default curve properly: should be \"Ed25519\" but is %q", p.defaultCurve)
	}
	if len(k) != 2 {
		t.Errorf("NewProvider() should return 2 public keys but instead returned %d", len(k))
	}
	p, k, err = NewProvider(Ed448)
	if err != nil {
		t.Errorf("NewProvider() returned an error: %s", err.Error())
	}
	if p.defaultCurve != Ed448 {
		t.Errorf("NewProvider() failed to set default curve properly: should be \"Ed448\" but is %q", p.defaultCurve)
	}
	if len(k) != 2 {
		t.Errorf("NewProvider() should return 2 public keys but instead returned %d", len(k))
	}
	_, _, err = NewProvider("unknown")
	if err == nil {
		t.Errorf("NewProvider() succeded for an unknown curve")
	}
	random := rand.Reader
	rand.Reader = bytes.NewReader(nil)
	_, _, err = NewProvider(Ed25519)
	if err == nil {
		t.Error("NewProvider() with invalid random generator did not fail")
	}
	b := [48]byte{0x00}
	rand.Reader = bytes.NewReader(b[:])
	_, _, err = NewProvider(Ed25519)
	if err == nil {
		t.Error("NewProvider() with invalid random generator did not fail")
	}
	rand.Reader = random
}

func TestNewProviderWithKeyURL(t *testing.T) {
	p, k, err := NewProviderWithKeyURL(Ed25519, "key_url")
	if err != nil {
		t.Errorf("NewProviderWithKeyURL() returned an error: %s", err.Error())
	}
	if p.defaultCurve != Ed25519 {
		t.Errorf("NewProviderWithKeyURL() failed to set default curve properly: should be \"Ed25519\" but is %q", p.defaultCurve)
	}
	if p.ed25519keyset.jku != "key_url" {
		t.Errorf("NewProviderWithKeyURL() failed to set key url for Ed25519KeySet: should be \"key_url\" but is %q", p.ed25519keyset.jku)
	}
	if p.ed448keyset.jku != "key_url" {
		t.Errorf("NewProviderWithKeyURL() failed to set key url for Ed448KeySet: should be \"key_url\" but is %q", p.ed448keyset.jku)
	}
	if len(k) != 2 {
		t.Errorf("NewProviderWithKeyURL() should return 2 public keys but instead returned %d", len(k))
	}
	random := rand.Reader
	rand.Reader = bytes.NewReader(nil)
	_, _, err = NewProviderWithKeyURL(Ed25519, "key_url")
	if err == nil {
		t.Error("NewProviderWithKeyURL() with invalid random generator did not fail")
	}
	rand.Reader = random
}

func TestLoadProvider(t *testing.T) {
	type args struct {
		k2           Ed25519KeySet
		k4           Ed448KeySet
		defaultCurve string
	}
	tests := []struct {
		name string
		args args
		want Provider
	}{
		{"Ed25519", args{Ed25519KeySet{}, Ed448KeySet{}, Ed25519}, Provider{Ed25519KeySet{}, Ed448KeySet{}, ed448.NewCurve(), Ed25519}},
		{"Ed448", args{Ed25519KeySet{}, Ed448KeySet{}, Ed448}, Provider{Ed25519KeySet{}, Ed448KeySet{}, ed448.NewCurve(), Ed448}},
		{"Unknown", args{Ed25519KeySet{}, Ed448KeySet{}, "unknown"}, Provider{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LoadProvider(tt.args.k2, tt.args.k4, tt.args.defaultCurve); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadProvider() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProvider_Header(t *testing.T) {
	h := jwt.Header{Typ: "JWT"}
	Provider{Ed25519KeySet{kid: "key_id", jku: "key_url"}, Ed448KeySet{}, ed448.NewCurve(), Ed25519}.Header(&h)
	if h.Alg != "EdDSA" {
		t.Errorf("Provider.Header() should set Alg to \"EdDSA\" but instead it is %q", h.Alg)
	}
	if h.Kid != "key_id" {
		t.Errorf("Provider.Header() should set Kid to \"key_id\" but instead it is %q", h.Kid)
	}
	if h.Jku != "key_url" {
		t.Errorf("Provider.Header() should set Jku to \"key_url\" but instead it is %q", h.Jku)
	}
	if h.Crv != Ed25519 {
		t.Errorf("Provider.Header() should set Crv to \"Ed25519\" but instead it is %q", h.Crv)
	}

	h = jwt.Header{Typ: "JWT"}
	Provider{Ed25519KeySet{}, Ed448KeySet{kid: "key_id", jku: "key_url"}, ed448.NewCurve(), Ed448}.Header(&h)
	if h.Alg != "EdDSA" {
		t.Errorf("Provider.Header() should set Alg to \"EdDSA\" but instead it is %q", h.Alg)
	}
	if h.Kid != "key_id" {
		t.Errorf("Provider.Header() should set Kid to \"key_id\" but instead it is %q", h.Kid)
	}
	if h.Jku != "key_url" {
		t.Errorf("Provider.Header() should set Jku to \"key_url\" but instead it is %q", h.Jku)
	}
	if h.Crv != Ed448 {
		t.Errorf("Provider.Header() should set Crv to \"Ed448\" but instead it is %q", h.Crv)
	}
}

func TestProvider_Sign(t *testing.T) {
	p25519 := Provider{Ed25519KeySet{canSign: false}, Ed448KeySet{}, ed448.NewCurve(), Ed25519}
	if _, err := p25519.Sign(nil); err == nil {
		t.Error("Provider.Sign() should fail because canSign is false for default curve")
	}
	p448 := Provider{Ed25519KeySet{}, Ed448KeySet{canSign: false}, ed448.NewCurve(), Ed448}
	if _, err := p448.Sign(nil); err == nil {
		t.Error("Provider.Sign() should fail because canSign is false for default curve")
	}
	p448invalid := Provider{Ed25519KeySet{}, Ed448KeySet{private: [144]byte{33, 147, 45, 233, 236, 0, 92, 221, 111, 132, 50, 172, 83, 220, 197, 251, 46, 83, 98, 113, 173, 250, 128, 15, 127, 85, 149, 81, 253, 149, 84, 233, 76, 193, 173, 2, 193, 133, 5, 110, 215, 167, 6, 246, 145, 232, 50, 246, 120, 203, 191, 73, 226, 187, 134, 244, 139, 144, 55, 7, 217, 55, 48, 50, 59, 69, 52, 245, 17, 88, 150, 144, 192, 86, 215, 194, 107, 27, 105, 18, 204, 119, 213, 231, 70, 116, 232, 126, 57, 115, 221, 8, 152, 154, 20, 204, 37, 255, 227, 237, 136, 58, 151, 207, 108, 214, 113, 87, 22, 144, 227, 121, 79, 213, 114, 45, 207, 192, 160, 60, 193, 149, 53, 220, 34, 103, 37, 25, 90, 18, 60, 190, 209, 191, 147, 242, 127, 173, 86, 221, 233, 192, 44, 167}, canSign: true}, ed448.NewCurve(), Ed448}
	if _, err := p448invalid.Sign(nil); err == nil {
		t.Error("Provider.Sign() should fail because Ed448 private key is invalid")
	}
	punknown := Provider{Ed25519KeySet{}, Ed448KeySet{}, ed448.NewCurve(), "unknown"}
	if _, err := punknown.Sign(nil); err == nil {
		t.Error("Provider.Sign() should fail because default curve is unknown")
	}
}

func TestProvider_Verify(t *testing.T) {
	p25519 := Provider{Ed25519KeySet{canVerify: false}, Ed448KeySet{}, ed448.NewCurve(), ""}
	if p25519.Verify(nil, nil, jwt.Header{Crv: Ed25519}) == nil {
		t.Error("Provider.Verify() should fail because canVerify is false for specified curve")
	}
	p448 := Provider{Ed25519KeySet{}, Ed448KeySet{canVerify: false}, ed448.NewCurve(), ""}
	if p448.Verify(nil, nil, jwt.Header{Crv: Ed448}) == nil {
		t.Error("Provider.Verify() should fail because canVerify is false for specified curve")
	}
	punknown := Provider{Ed25519KeySet{}, Ed448KeySet{}, ed448.NewCurve(), ""}
	if punknown.Verify(nil, nil, jwt.Header{Crv: "unknown"}) == nil {
		t.Error("Provider.Verify() should fail because specified curve is unknown")
	}
}
