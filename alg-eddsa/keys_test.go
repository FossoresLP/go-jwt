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
	ed25519PublicKey = [32]byte{0x4a, 0x84, 0x0b, 0x8b, 0xcf, 0x8d, 0xac, 0xe4, 0xfe, 0x25, 0x86, 0x1d, 0xe2, 0x96, 0xfe, 0x0a, 0xd3, 0x7c, 0xdd, 0x9d, 0xb2, 0xf6, 0xd6, 0x28, 0x85, 0xb3, 0x86, 0x6d, 0x78, 0xe9, 0xb7, 0x9f}
	ed448PublicKey   = [56]byte{0x00}
)

func TestProvider_AddPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		p       *Provider
		key     publickey.PublicKey
		wantErr bool
	}{
		{"Ed25519", &Provider{c2: make(map[string]ed25519.PublicKey), c4: make(map[string][56]byte)}, publickey.New(ed25519PublicKey[:], "key_id"), false},
		{"Ed25519 already exists", &Provider{c2: map[string]ed25519.PublicKey{"key_id": ed25519.PublicKey(ed25519PublicKey[:])}, c4: make(map[string][56]byte)}, publickey.New(ed25519PublicKey[:], "key_id"), true},
		{"Ed448", &Provider{c2: make(map[string]ed25519.PublicKey), c4: make(map[string][56]byte)}, publickey.New(ed448PublicKey[:], "key_id"), false},
		{"Ed448 already exists", &Provider{c2: make(map[string]ed25519.PublicKey), c4: map[string][56]byte{"key_id": ed448PublicKey}}, publickey.New(ed448PublicKey[:], "key_id"), true},
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
		{"Ed25519", Provider{curve: Ed25519, settings: Settings{kid: "key_id"}, c2: map[string]ed25519.PublicKey{"key_id": ed25519.PublicKey(ed25519PublicKey[:])}}, publickey.New(ed25519PublicKey[:], "key_id")},
		{"Ed448", Provider{curve: Ed448, settings: Settings{kid: "key_id"}, c4: map[string][56]byte{"key_id": ed448PublicKey}}, publickey.New(ed448PublicKey[:], "key_id")},
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
