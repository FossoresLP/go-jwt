package eddsa

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/fossoreslp/go-jwt/jwk"
	"golang.org/x/crypto/ed25519"
)

var (
	ed25519PrivateKey    = [64]byte{0x40, 0xb7, 0xd9, 0xb5, 0x60, 0x97, 0x87, 0xfd, 0xee, 0x7d, 0x4e, 0xf9, 0x34, 0xa5, 0xfd, 0x44, 0xc1, 0x8b, 0x80, 0xfa, 0xd9, 0xfd, 0x2f, 0x5a, 0x73, 0xa6, 0x70, 0xc2, 0xab, 0x2c, 0xcb, 0x2e, 0x4a, 0x84, 0x0b, 0x8b, 0xcf, 0x8d, 0xac, 0xe4, 0xfe, 0x25, 0x86, 0x1d, 0xe2, 0x96, 0xfe, 0x0a, 0xd3, 0x7c, 0xdd, 0x9d, 0xb2, 0xf6, 0xd6, 0x28, 0x85, 0xb3, 0x86, 0x6d, 0x78, 0xe9, 0xb7, 0x9f}
	ed25519Seed          = [32]byte{0x40, 0xb7, 0xd9, 0xb5, 0x60, 0x97, 0x87, 0xfd, 0xee, 0x7d, 0x4e, 0xf9, 0x34, 0xa5, 0xfd, 0x44, 0xc1, 0x8b, 0x80, 0xfa, 0xd9, 0xfd, 0x2f, 0x5a, 0x73, 0xa6, 0x70, 0xc2, 0xab, 0x2c, 0xcb, 0x2e}
	ed25519PrivJWK, _    = jwk.NewEdDSAPrivateKey(ed25519Seed[:], ed25519PublicKey[:], "key_id")
	ed448PrivateKey      = [144]byte{0xFF}
	ed448PrivJWK, _      = jwk.NewEdDSAPrivateKey(ed448PrivateKey[:], ed448PublicKey[:], "key_id")
	ed448EmptyPrivateKey = [144]byte{0x0}
)

func TestNewSettings(t *testing.T) {
	tests := []struct {
		name    string
		key     jwk.JWK
		want    Settings
		wantErr bool
	}{
		{"Normal", ed25519PrivJWK, Settings{Ed25519, ed25519.PrivateKey(ed25519PrivateKey[:]), ed448EmptyPrivateKey, "key_id", ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSettings(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSettings() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSettings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewSettingsWithKeyURL(t *testing.T) {
	type args struct {
		key    jwk.JWK
		keyurl string
	}
	tests := []struct {
		name    string
		args    args
		want    Settings
		wantErr bool
	}{
		{"Ed25519", args{ed25519PrivJWK, "key_url"}, Settings{Ed25519, ed25519.PrivateKey(ed25519PrivateKey[:]), ed448EmptyPrivateKey, "key_id", "key_url"}, false},
		{"Ed448", args{ed448PrivJWK, "key_url"}, Settings{Ed448, ed25519.PrivateKey(nil), ed448PrivateKey, "key_id", "key_url"}, false},
		{"Wrong length", args{invalidJWK, "key_url"}, Settings{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSettingsWithKeyURL(tt.args.key, tt.args.keyurl)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSettingsWithKeyID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSettingsWithKeyID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_generateEd25519Keys(t *testing.T) {
	random := rand.Reader
	rand.Reader = bytes.NewReader(nil)
	_, _, _, err := generateEd25519Keys()
	if err == nil {
		t.Error("Generating new Ed25519 keys did not fail with invalid random generator")
	}
	b := [32]byte{0x00}
	rand.Reader = bytes.NewReader(b[:])
	_, _, _, err = generateEd25519Keys()
	if err == nil {
		t.Error("Generating new UUID for key did not fail with empty random generator")
	}
	rand.Reader = random
}

func Test_generateEd448Keys(t *testing.T) {
	random := rand.Reader
	rand.Reader = bytes.NewReader(nil)
	_, _, _, err := generateEd448Keys()
	if err == nil {
		t.Error("Generating new Ed448 keys did not fail with invalid random generator")
	}
	b := [32]byte{0x00}
	rand.Reader = bytes.NewReader(b[:])
	_, _, _, err = generateEd448Keys()
	if err == nil {
		t.Error("Generating new UUID for key did not fail with empty random generator")
	}
	rand.Reader = random
}

var (
	ed25519PublicKey = [32]byte{0x4a, 0x84, 0x0b, 0x8b, 0xcf, 0x8d, 0xac, 0xe4, 0xfe, 0x25, 0x86, 0x1d, 0xe2, 0x96, 0xfe, 0x0a, 0xd3, 0x7c, 0xdd, 0x9d, 0xb2, 0xf6, 0xd6, 0x28, 0x85, 0xb3, 0x86, 0x6d, 0x78, 0xe9, 0xb7, 0x9f}
	ed448PublicKey   = [56]byte{0x00}
	ed25519PubJWK, _ = jwk.NewEdDSAPublicKey(ed25519PublicKey[:], "key_id")
	ed448PubJWK, _   = jwk.NewEdDSAPublicKey(ed448PublicKey[:], "key_id")
	invalidJWK       = jwk.NewBasic(nil, "key_id")
)

func TestProvider_AddPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		p       *Provider
		key     jwk.JWK
		wantErr bool
	}{
		{"Ed25519", &Provider{c2: make(map[string]ed25519.PublicKey), c4: make(map[string][56]byte)}, ed25519PubJWK, false},
		{"Ed25519 already exists", &Provider{c2: map[string]ed25519.PublicKey{"key_id": ed25519.PublicKey(ed25519PublicKey[:])}, c4: make(map[string][56]byte)}, ed25519PubJWK, true},
		{"Ed448", &Provider{c2: make(map[string]ed25519.PublicKey), c4: make(map[string][56]byte)}, ed448PubJWK, false},
		{"Ed448 already exists", &Provider{c2: make(map[string]ed25519.PublicKey), c4: map[string][56]byte{"key_id": ed448PublicKey}}, ed448PubJWK, true},
		{"Invalid JWK", &Provider{c2: make(map[string]ed25519.PublicKey), c4: make(map[string][56]byte)}, invalidJWK, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.AddPublicKey(tt.key); (err != nil) != tt.wantErr {
				t.Errorf("Provider.AddPublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProvider_RemovePublicKey(t *testing.T) {
	tests := []struct {
		name  string
		p     *Provider
		keyid string
	}{
		{"Normal", &Provider{c2: make(map[string]ed25519.PublicKey), c4: make(map[string][56]byte)}, "key_id"},
		{"Same as signing key", &Provider{settings: Settings{kid: "key_id"}, c2: make(map[string]ed25519.PublicKey), c4: make(map[string][56]byte)}, "key_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.RemovePublicKey(tt.keyid)
		})
	}
}

func TestProvider_CurrentKey(t *testing.T) {
	tests := []struct {
		name string
		p    Provider
		want jwk.JWK
	}{
		{"Ed25519", Provider{curve: Ed25519, settings: Settings{kid: "key_id"}, c2: map[string]ed25519.PublicKey{"key_id": ed25519.PublicKey(ed25519PublicKey[:])}}, ed25519PubJWK},
		{"Ed448", Provider{curve: Ed448, settings: Settings{kid: "key_id"}, c4: map[string][56]byte{"key_id": ed448PublicKey}}, ed448PubJWK},
		{"Invalid curve", Provider{curve: 12}, jwk.JWK{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.CurrentKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Provider.CurrentKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
