package es

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"reflect"
	"testing"

	"github.com/fossoreslp/go-jwt/publickey"
)

var (
	x, _      = new(big.Int).SetString("53362156244743717582302245396579768295291970453913383836603205696230085410059", 10)
	y, _      = new(big.Int).SetString("30291755020966801726600908749968268600863491590438969900821061765762053214603", 10)
	d, _      = new(big.Int).SetString("81441865675641311106028598596990373907775388393469674002729224480451685045463", 10)
	priv      = &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	ec        = []byte{0x30, 0x77, 0x2, 0x1, 0x1, 0x4, 0x20, 0xb4, 0xe, 0x76, 0x62, 0xe0, 0x1f, 0x27, 0x4d, 0x77, 0x7d, 0x23, 0xcd, 0x82, 0xe9, 0xd2, 0x1d, 0x3b, 0xf8, 0x40, 0xf7, 0xf4, 0x9f, 0x22, 0xf8, 0xb6, 0x36, 0xca, 0xd6, 0xa0, 0xb8, 0xd4, 0xd7, 0xa0, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0xa1, 0x44, 0x3, 0x42, 0x0, 0x4, 0x75, 0xf9, 0xe8, 0xfd, 0x91, 0xc8, 0x84, 0x61, 0x5, 0xaa, 0xd4, 0x1d, 0x6a, 0x36, 0xb3, 0xce, 0xdc, 0xa2, 0x62, 0x82, 0x35, 0xc2, 0xf9, 0xb8, 0x1, 0x1a, 0xdb, 0xca, 0x77, 0xec, 0xbd, 0xb, 0x42, 0xf8, 0x86, 0x98, 0x63, 0x8c, 0xbf, 0x9b, 0xca, 0xab, 0xa3, 0x39, 0x9c, 0xc1, 0x2, 0x35, 0xb8, 0x5a, 0x49, 0x25, 0x52, 0xb0, 0xa0, 0x4, 0xe2, 0xe7, 0xf2, 0x15, 0x79, 0xaa, 0x91, 0x8b}
	pkcs8     = []byte{0x30, 0x81, 0x87, 0x2, 0x1, 0x0, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x4, 0x6d, 0x30, 0x6b, 0x2, 0x1, 0x1, 0x4, 0x20, 0xb4, 0xe, 0x76, 0x62, 0xe0, 0x1f, 0x27, 0x4d, 0x77, 0x7d, 0x23, 0xcd, 0x82, 0xe9, 0xd2, 0x1d, 0x3b, 0xf8, 0x40, 0xf7, 0xf4, 0x9f, 0x22, 0xf8, 0xb6, 0x36, 0xca, 0xd6, 0xa0, 0xb8, 0xd4, 0xd7, 0xa1, 0x44, 0x3, 0x42, 0x0, 0x4, 0x75, 0xf9, 0xe8, 0xfd, 0x91, 0xc8, 0x84, 0x61, 0x5, 0xaa, 0xd4, 0x1d, 0x6a, 0x36, 0xb3, 0xce, 0xdc, 0xa2, 0x62, 0x82, 0x35, 0xc2, 0xf9, 0xb8, 0x1, 0x1a, 0xdb, 0xca, 0x77, 0xec, 0xbd, 0xb, 0x42, 0xf8, 0x86, 0x98, 0x63, 0x8c, 0xbf, 0x9b, 0xca, 0xab, 0xa3, 0x39, 0x9c, 0xc1, 0x2, 0x35, 0xb8, 0x5a, 0x49, 0x25, 0x52, 0xb0, 0xa0, 0x4, 0xe2, 0xe7, 0xf2, 0x15, 0x79, 0xaa, 0x91, 0x8b}
	pkcs8_rsa = []byte{0x30, 0x42, 0x2, 0x1, 0x0, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1, 0x5, 0x0, 0x4, 0x2e, 0x30, 0x2c, 0x2, 0x1, 0x0, 0x2, 0x5, 0x0, 0xd6, 0xc8, 0xbc, 0x87, 0x2, 0x3, 0x1, 0x0, 0x1, 0x2, 0x4, 0x28, 0x39, 0x64, 0x21, 0x2, 0x3, 0x0, 0xfa, 0x3f, 0x2, 0x3, 0x0, 0xdb, 0xb9, 0x2, 0x2, 0x50, 0xed, 0x2, 0x3, 0x0, 0xa6, 0x49, 0x2, 0x2, 0x1d, 0xb0}
	pub       = ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	pkix      = []byte{0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x75, 0xf9, 0xe8, 0xfd, 0x91, 0xc8, 0x84, 0x61, 0x5, 0xaa, 0xd4, 0x1d, 0x6a, 0x36, 0xb3, 0xce, 0xdc, 0xa2, 0x62, 0x82, 0x35, 0xc2, 0xf9, 0xb8, 0x1, 0x1a, 0xdb, 0xca, 0x77, 0xec, 0xbd, 0xb, 0x42, 0xf8, 0x86, 0x98, 0x63, 0x8c, 0xbf, 0x9b, 0xca, 0xab, 0xa3, 0x39, 0x9c, 0xc1, 0x2, 0x35, 0xb8, 0x5a, 0x49, 0x25, 0x52, 0xb0, 0xa0, 0x4, 0xe2, 0xe7, 0xf2, 0x15, 0x79, 0xaa, 0x91, 0x8b}
	pkix_rsa  = []byte{0x30, 0x20, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1, 0x5, 0x0, 0x3, 0xf, 0x0, 0x30, 0xc, 0x2, 0x5, 0x0, 0xd6, 0xc8, 0xbc, 0x87, 0x2, 0x3, 0x1, 0x0, 0x1}
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
		{"EC key", args{ec, "key_id"}, Settings{priv, "key_id", ""}, false},
		{"PKCS8 key", args{pkcs8, "key_id"}, Settings{priv, "key_id", ""}, false},
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
		{"EC key", args{ec, "key_id", "key_url"}, Settings{priv, "key_id", "key_url"}, false},
		{"PKCS8 key", args{pkcs8, "key_id", "key_url"}, Settings{priv, "key_id", "key_url"}, false},
		{"Invalid", args{[]byte("invalid key"), "key_id", "key_url"}, Settings{}, true},
		{"PKCS8 RSA key", args{pkcs8_rsa, "key_id", "key_url"}, Settings{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSettingsWithKeyURL(tt.args.key, tt.args.keyid, tt.args.keyurl)
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
	type args struct {
		key publickey.PublicKey
	}
	tests := []struct {
		name    string
		p       *Provider
		args    args
		wantErr bool
	}{
		{"Normal", &Provider{keys: make(map[string]*ecdsa.PublicKey)}, args{publickey.New(pkix, "key_id")}, false},
		{"Already exists", &Provider{keys: map[string]*ecdsa.PublicKey{"key_id": &pub}}, args{publickey.New(pkix, "key_id")}, true},
		{"Invalid", &Provider{keys: make(map[string]*ecdsa.PublicKey)}, args{publickey.New([]byte("invalid key"), "key_id")}, true},
		{"PKIX RSA key", &Provider{keys: make(map[string]*ecdsa.PublicKey)}, args{publickey.New(pkix_rsa, "key_id")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.AddPublicKey(tt.args.key); (err != nil) != tt.wantErr {
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
		{"Normal", &Provider{settings: Settings{kid: "signing_key"}, keys: make(map[string]*ecdsa.PublicKey)}, "key_id"},
		{"Same as signing key", &Provider{settings: Settings{kid: "signing_key"}, keys: make(map[string]*ecdsa.PublicKey)}, "signing_key"},
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
		{"Normal", Provider{settings: Settings{private: priv, kid: "key_id"}}, publickey.New(pkix, "key_id")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.CurrentKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Provider.CurrentKey() = %v, want %v", got, tt.want)
			}
		})
	}
}