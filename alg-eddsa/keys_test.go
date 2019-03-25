package eddsa

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/fossoreslp/go-jwt/publickey"
	"golang.org/x/crypto/ed25519"
)

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
	ed25519_public_key = [32]byte{0x00}
	ed448_public_key   = [56]byte{0x00}
)

func TestProvider_AddPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		p       *Provider
		key     publickey.PublicKey
		wantErr bool
	}{
		{"Ed25519", &Provider{c2: make(map[string]ed25519.PublicKey), c4: make(map[string][56]byte)}, publickey.New(ed25519_public_key[:], "key_id"), false},
		{"Ed25519 already exists", &Provider{c2: map[string]ed25519.PublicKey{"key_id": ed25519.PublicKey(ed25519_public_key[:])}, c4: make(map[string][56]byte)}, publickey.New(ed25519_public_key[:], "key_id"), true},
		{"Ed448", &Provider{c2: make(map[string]ed25519.PublicKey), c4: make(map[string][56]byte)}, publickey.New(ed448_public_key[:], "key_id"), false},
		{"Ed448 already exists", &Provider{c2: make(map[string]ed25519.PublicKey), c4: map[string][56]byte{"key_id": ed448_public_key}}, publickey.New(ed448_public_key[:], "key_id"), true},
		{"Invalid public key length", &Provider{c2: make(map[string]ed25519.PublicKey), c4: make(map[string][56]byte)}, publickey.New(nil, "key_id"), true},
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
		want publickey.PublicKey
	}{
		{"Ed25519", Provider{curve: Ed25519, settings: Settings{kid: "key_id"}, c2: map[string]ed25519.PublicKey{"key_id": ed25519.PublicKey(ed25519_public_key[:])}}, publickey.New(ed25519_public_key[:], "key_id")},
		{"Ed448", Provider{curve: Ed448, settings: Settings{kid: "key_id"}, c4: map[string][56]byte{"key_id": ed448_public_key}}, publickey.New(ed448_public_key[:], "key_id")},
		{"Invalid curve", Provider{curve: 12}, publickey.PublicKey{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.CurrentKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Provider.CurrentKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
