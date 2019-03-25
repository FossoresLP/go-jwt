package hs

import (
	"reflect"
	"testing"

	"github.com/fossoreslp/go-jwt/publickey"
)

func TestNewSettings(t *testing.T) {
	type args struct {
		key   []byte
		keyID string
	}
	tests := []struct {
		name    string
		args    args
		want    Settings
		wantErr bool
	}{
		{"Normal", args{[]byte("test"), "key_id"}, Settings{[]byte("test"), "key_id", ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSettings(tt.args.key, tt.args.keyID)
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
		keyID  string
		keyURL string
	}
	tests := []struct {
		name    string
		args    args
		want    Settings
		wantErr bool
	}{
		{"Normal", args{[]byte("test"), "key_id", "key_url"}, Settings{[]byte("test"), "key_id", "key_url"}, false},
		{"Empty key", args{[]byte(""), "key_id", "key_url"}, Settings{}, true},
		{"Nil key", args{nil, "key_id", "key_url"}, Settings{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSettingsWithKeyURL(tt.args.key, tt.args.keyID, tt.args.keyURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSettingsWithKeyURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSettingsWithKeyURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProvider_AddPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		p       *Provider
		key     publickey.PublicKey
		wantErr bool
	}{
		{"Normal", &Provider{keys: map[string][]byte{}}, publickey.New([]byte("test"), "key_id"), false},
		{"Key already exists", &Provider{keys: map[string][]byte{"key_id": []byte("test")}}, publickey.New([]byte("test"), "key_id"), true},
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
		{"Normal", &Provider{settings: Settings{kid: "signing_key"}, keys: map[string][]byte{}}, "key_id"},
		{"Try deleting signing key", &Provider{settings: Settings{kid: "signing_key"}, keys: map[string][]byte{}}, "signing_key"},
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
		{"Normal", Provider{settings: Settings{key: []byte("test"), kid: "key_id"}}, publickey.New([]byte("test"), "key_id")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.CurrentKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Provider.CurrentKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
