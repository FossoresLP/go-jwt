package eddsa

import (
	"reflect"
	"testing"

	"golang.org/x/crypto/ed25519"
)

var (
	ed25519PrivateKey    = [64]byte{0x40, 0xb7, 0xd9, 0xb5, 0x60, 0x97, 0x87, 0xfd, 0xee, 0x7d, 0x4e, 0xf9, 0x34, 0xa5, 0xfd, 0x44, 0xc1, 0x8b, 0x80, 0xfa, 0xd9, 0xfd, 0x2f, 0x5a, 0x73, 0xa6, 0x70, 0xc2, 0xab, 0x2c, 0xcb, 0x2e, 0x4a, 0x84, 0x0b, 0x8b, 0xcf, 0x8d, 0xac, 0xe4, 0xfe, 0x25, 0x86, 0x1d, 0xe2, 0x96, 0xfe, 0x0a, 0xd3, 0x7c, 0xdd, 0x9d, 0xb2, 0xf6, 0xd6, 0x28, 0x85, 0xb3, 0x86, 0x6d, 0x78, 0xe9, 0xb7, 0x9f}
	ed25519Seed          = [32]byte{0x40, 0xb7, 0xd9, 0xb5, 0x60, 0x97, 0x87, 0xfd, 0xee, 0x7d, 0x4e, 0xf9, 0x34, 0xa5, 0xfd, 0x44, 0xc1, 0x8b, 0x80, 0xfa, 0xd9, 0xfd, 0x2f, 0x5a, 0x73, 0xa6, 0x70, 0xc2, 0xab, 0x2c, 0xcb, 0x2e}
	ed448PrivateKey      = [144]byte{0xFF}
	ed448EmptyPrivateKey = [144]byte{0x0}
)

func TestNewSettings(t *testing.T) {

	type args struct {
		key   []byte
		keyid string
	}
	tests := []struct {
		name    string
		args    args
		want    Settings
		wantErr bool
	}{
		{"Normal", args{ed25519Seed[:], "key_id"}, Settings{Ed25519, ed25519.PrivateKey(ed25519PrivateKey[:]), ed448EmptyPrivateKey, "key_id", ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSettings(tt.args.key, tt.args.keyid)
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
		key    []byte
		keyid  string
		keyurl string
	}
	tests := []struct {
		name    string
		args    args
		want    Settings
		wantErr bool
	}{
		{"Ed25519", args{ed25519Seed[:], "key_id", "key_url"}, Settings{Ed25519, ed25519.PrivateKey(ed25519PrivateKey[:]), ed448EmptyPrivateKey, "key_id", "key_url"}, false},
		{"Ed448", args{ed448PrivateKey[:], "key_id", "key_url"}, Settings{Ed448, ed25519.PrivateKey(nil), ed448PrivateKey, "key_id", "key_url"}, false},
		{"Wrong length", args{nil, "key_id", "key_url"}, Settings{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSettingsWithKeyURL(tt.args.key, tt.args.keyid, tt.args.keyurl)
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
