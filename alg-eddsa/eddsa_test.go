package eddsa

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/fossoreslp/go-jwt"
	"golang.org/x/crypto/ed25519"
)

func TestNewProvider(t *testing.T) {
	p, err := NewProvider(Ed25519)
	if err != nil {
		t.Errorf("NewProvider() returned an error: %s", err.Error())
	}
	if p.curve != Ed25519 {
		t.Errorf("NewProvider() failed to set default curve properly: should be \"Ed25519\" but is %q", p.curve)
	}
	p, err = NewProvider(Ed448)
	if err != nil {
		t.Errorf("NewProvider() returned an error: %s", err.Error())
	}
	if p.curve != Ed448 {
		t.Errorf("NewProvider() failed to set default curve properly: should be \"Ed448\" but is %q", p.curve)
	}
	_, err = NewProvider(12)
	if err == nil {
		t.Errorf("NewProvider() succeded for an unknown curve")
	}
	random := rand.Reader
	rand.Reader = bytes.NewReader(nil)
	_, err = NewProvider(Ed25519)
	if err == nil {
		t.Error("NewProvider() with invalid random generator did not fail")
	}
	_, err = NewProvider(Ed448)
	if err == nil {
		t.Error("NewProvider() with invalid random generator did not fail")
	}
	rand.Reader = random
}

func TestNewProviderWithKeyURL(t *testing.T) {
	p, err := NewProviderWithKeyURL(Ed25519, "key_url")
	if err != nil {
		t.Errorf("NewProviderWithKeyURL() returned an error: %s", err.Error())
	}
	if p.curve != Ed25519 {
		t.Errorf("NewProviderWithKeyURL() failed to set default curve properly: should be \"Ed25519\" but is %q", p.curve)
	}
	if p.settings.jku != "key_url" {
		t.Errorf("NewProviderWithKeyURL() failed to set key url: should be \"key_url\" but is %q", p.settings.jku)
	}
	random := rand.Reader
	rand.Reader = bytes.NewReader(nil)
	_, err = NewProviderWithKeyURL(Ed25519, "key_url")
	if err == nil {
		t.Error("NewProviderWithKeyURL() with invalid random generator did not fail")
	}
	rand.Reader = random
}

func TestLoadProvider(t *testing.T) {
	type args struct {
		settings Settings
		curve    int
	}
	tests := []struct {
		name    string
		args    args
		want    Provider
		wantErr bool
	}{
		{"Ed25519 invalid settings type", args{Settings{}, Ed25519}, Provider{}, true},
		{"Ed448 invalid settings type", args{Settings{}, Ed448}, Provider{}, true},
		{"Ed25519", args{Settings{typ: Ed25519, ed25519: ed25519PrivateKey[:], kid: "key_id"}, Ed25519}, Provider{Settings{typ: Ed25519, ed25519: ed25519PrivateKey[:], kid: "key_id"}, map[string]ed25519.PublicKey{"": ed25519.PublicKey(ed25519PublicKey[:]), "key_id": ed25519.PublicKey(ed25519PublicKey[:])}, map[string][56]byte{}, Ed25519}, false},
		{"Ed448", args{Settings{typ: Ed448, ed448: ed448PrivateKey, kid: "key_id"}, Ed448}, Provider{Settings{typ: Ed448, ed448: ed448PrivateKey, kid: "key_id"}, map[string]ed25519.PublicKey{}, map[string][56]byte{"": ed448PublicKey, "key_id": ed448PublicKey}, Ed448}, false},
		{"Unknown", args{Settings{}, 12}, Provider{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadProvider(tt.args.settings, tt.args.curve)
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
	Provider{Settings{kid: "key_id", jku: "key_url"}, nil, nil, Ed25519}.Header(&h)
	if h.Alg != "EdDSA" {
		t.Errorf("Provider.Header() should set Alg to \"EdDSA\" but instead it is %q", h.Alg)
	}
	if h.Kid != "key_id" {
		t.Errorf("Provider.Header() should set Kid to \"key_id\" but instead it is %q", h.Kid)
	}
	if h.Jku != "key_url" {
		t.Errorf("Provider.Header() should set Jku to \"key_url\" but instead it is %q", h.Jku)
	}
	if h.Crv != "Ed25519" {
		t.Errorf("Provider.Header() should set Crv to \"Ed25519\" but instead it is %q", h.Crv)
	}

	h = jwt.Header{Typ: "JWT"}
	Provider{Settings{kid: "key_id", jku: "key_url"}, nil, nil, Ed448}.Header(&h)
	if h.Alg != "EdDSA" {
		t.Errorf("Provider.Header() should set Alg to \"EdDSA\" but instead it is %q", h.Alg)
	}
	if h.Kid != "key_id" {
		t.Errorf("Provider.Header() should set Kid to \"key_id\" but instead it is %q", h.Kid)
	}
	if h.Jku != "key_url" {
		t.Errorf("Provider.Header() should set Jku to \"key_url\" but instead it is %q", h.Jku)
	}
	if h.Crv != "Ed448" {
		t.Errorf("Provider.Header() should set Crv to \"Ed448\" but instead it is %q", h.Crv)
	}
}

func TestProvider_Sign(t *testing.T) {
	p448invalid := Provider{Settings{typ: Ed448, ed448: [144]byte{33, 147, 45, 233, 236, 0, 92, 221, 111, 132, 50, 172, 83, 220, 197, 251, 46, 83, 98, 113, 173, 250, 128, 15, 127, 85, 149, 81, 253, 149, 84, 233, 76, 193, 173, 2, 193, 133, 5, 110, 215, 167, 6, 246, 145, 232, 50, 246, 120, 203, 191, 73, 226, 187, 134, 244, 139, 144, 55, 7, 217, 55, 48, 50, 59, 69, 52, 245, 17, 88, 150, 144, 192, 86, 215, 194, 107, 27, 105, 18, 204, 119, 213, 231, 70, 116, 232, 126, 57, 115, 221, 8, 152, 154, 20, 204, 37, 255, 227, 237, 136, 58, 151, 207, 108, 214, 113, 87, 22, 144, 227, 121, 79, 213, 114, 45, 207, 192, 160, 60, 193, 149, 53, 220, 34, 103, 37, 25, 90, 18, 60, 190, 209, 191, 147, 242, 127, 173, 86, 221, 233, 192, 44, 167}}, nil, nil, Ed448}
	if _, err := p448invalid.Sign(nil); err == nil {
		t.Error("Provider.Sign() should fail because Ed448 private key is invalid")
	}
	punknown := Provider{Settings{}, nil, nil, 12}
	if _, err := punknown.Sign(nil); err == nil {
		t.Error("Provider.Sign() should fail because default curve is unknown")
	}
}

func TestProvider_Verify(t *testing.T) {
	p25519 := Provider{Settings{kid: "test"}, map[string]ed25519.PublicKey{"test": ed25519.PublicKey{0x9a, 0xe1, 0x6f, 0x74, 0x0d, 0xc1, 0x49, 0x0a, 0xa7, 0x36, 0x9f, 0xb5, 0xce, 0x09, 0xe6, 0x07, 0xa3, 0xd9, 0x78, 0xd4, 0x8e, 0xa2, 0x87, 0x19, 0x1e, 0x92, 0x95, 0x5b, 0xa2, 0x9d, 0x74, 0xb2}}, nil, Ed25519}
	// Unknown public key
	if p25519.Verify([]byte("test"), []byte("signature"), jwt.Header{Crv: "Ed25519"}) == nil {
		t.Error("Provider.Verify() should fail for unknown public key")
	}
	p25519.c2[""] = ed25519.PublicKey{0x9a, 0xe1, 0x6f, 0x74, 0x0d, 0xc1, 0x49, 0x0a, 0xa7, 0x36, 0x9f, 0xb5, 0xce, 0x09, 0xe6, 0x07, 0xa3, 0xd9, 0x78, 0xd4, 0x8e, 0xa2, 0x87, 0x19, 0x1e, 0x92, 0x95, 0x5b, 0xa2, 0x9d, 0x74, 0xb2}
	// Invalid signature with public key "test"
	if p25519.Verify([]byte("test"), []byte("signature"), jwt.Header{Crv: "Ed25519", Kid: "test"}) == nil {
		t.Error("Provider.Verify() should fail for invalid signature")
	}
	// Invalid signature with public key "" (default public key)
	if p25519.Verify([]byte("test"), []byte("signature"), jwt.Header{Crv: "Ed25519"}) == nil {
		t.Error("Provider.Verify() should fail for invalid signature")
	}
	p448 := Provider{Settings{kid: "test"}, nil, map[string][56]byte{"test": [56]byte{0x65, 0x0d, 0x46, 0xb1, 0x0c, 0x4f, 0xd2, 0x2e, 0xd9, 0x4c, 0x97, 0x34, 0x49, 0x88, 0x16, 0xd1, 0xc8, 0x6a, 0x34, 0xa7, 0xae, 0x4d, 0xcb, 0x81, 0x4c, 0xd9, 0x45, 0xfb, 0x31, 0x4d, 0xe2, 0xaa, 0x04, 0xde, 0x17, 0xee, 0xf5, 0xae, 0x27, 0x29, 0xa0, 0x33, 0x25, 0x98, 0x27, 0x3f, 0xce, 0x9d, 0xe1, 0x4c, 0xf3, 0x24, 0x6b, 0x89, 0x4b, 0x60}}, Ed448}
	// Unknown public key
	if p448.Verify([]byte("test"), []byte("signature"), jwt.Header{Crv: "Ed448"}) == nil {
		t.Error("Provider.Verify() should fail for unknown public key")
	}
	p448.c4[""] = [56]byte{0x65, 0x0d, 0x46, 0xb1, 0x0c, 0x4f, 0xd2, 0x2e, 0xd9, 0x4c, 0x97, 0x34, 0x49, 0x88, 0x16, 0xd1, 0xc8, 0x6a, 0x34, 0xa7, 0xae, 0x4d, 0xcb, 0x81, 0x4c, 0xd9, 0x45, 0xfb, 0x31, 0x4d, 0xe2, 0xaa, 0x04, 0xde, 0x17, 0xee, 0xf5, 0xae, 0x27, 0x29, 0xa0, 0x33, 0x25, 0x98, 0x27, 0x3f, 0xce, 0x9d, 0xe1, 0x4c, 0xf3, 0x24, 0x6b, 0x89, 0x4b, 0x60}
	// Invalid signature with public key "test"
	if p448.Verify([]byte("test"), []byte("signature"), jwt.Header{Crv: "Ed448", Kid: "test"}) == nil {
		t.Error("Provider.Verify() should fail for invalid signature")
	}
	// Invalid signature with public key "" (default public key)
	if p448.Verify([]byte("test"), []byte("signature"), jwt.Header{Crv: "Ed448"}) == nil {
		t.Error("Provider.Verify() should fail for invalid signature")
	}
	punknown := Provider{}
	if punknown.Verify(nil, nil, jwt.Header{Crv: "unknown"}) == nil {
		t.Error("Provider.Verify() should fail because specified curve is unknown")
	}
}
