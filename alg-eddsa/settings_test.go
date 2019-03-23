package eddsa

import (
	"reflect"
	"testing"

	"golang.org/x/crypto/ed25519"
)

var (
	ed25519_private_key     = [64]byte{0xFF}
	ed448_private_key       = [144]byte{0xFF}
	ed448_empty_private_key = [144]byte{0x0}
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
		{"Normal", args{ed25519_private_key[:], "key_id"}, Settings{Ed25519, ed25519.PrivateKey(ed25519_private_key[:]), ed448_empty_private_key, "key_id", ""}, false},
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

func TestNewSettingsWithKeyID(t *testing.T) {
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
		{"Ed25519", args{ed25519_private_key[:], "key_id", "key_url"}, Settings{Ed25519, ed25519.PrivateKey(ed25519_private_key[:]), ed448_empty_private_key, "key_id", "key_url"}, false},
		{"Ed448", args{ed448_private_key[:], "key_id", "key_url"}, Settings{Ed448, ed25519.PrivateKey(nil), ed448_private_key, "key_id", "key_url"}, false},
		{"Wrong length", args{nil, "key_id", "key_url"}, Settings{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSettingsWithKeyID(tt.args.key, tt.args.keyid, tt.args.keyurl)
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
