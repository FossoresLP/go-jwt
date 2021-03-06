package ps

import (
	"crypto/rsa"
	"math/big"
	"reflect"
	"testing"

	"github.com/fossoreslp/go-jwt/publickey"
)

var (
	priv    = &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(3603479687), E: 65537}, D: big.NewInt(674849825), Primes: []*big.Int{big.NewInt(64063), big.NewInt(56249)}, Precomputed: rsa.PrecomputedValues{Dp: big.NewInt(20717), Dq: big.NewInt(42569), Qinv: big.NewInt(7600), CRTValues: []rsa.CRTValue{}}}
	pkcs1   = []byte{0x30, 0x2c, 0x2, 0x1, 0x0, 0x2, 0x5, 0x0, 0xd6, 0xc8, 0xbc, 0x87, 0x2, 0x3, 0x1, 0x0, 0x1, 0x2, 0x4, 0x28, 0x39, 0x64, 0x21, 0x2, 0x3, 0x0, 0xfa, 0x3f, 0x2, 0x3, 0x0, 0xdb, 0xb9, 0x2, 0x2, 0x50, 0xed, 0x2, 0x3, 0x0, 0xa6, 0x49, 0x2, 0x2, 0x1d, 0xb0}
	pkcs8   = []byte{0x30, 0x42, 0x2, 0x1, 0x0, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1, 0x5, 0x0, 0x4, 0x2e, 0x30, 0x2c, 0x2, 0x1, 0x0, 0x2, 0x5, 0x0, 0xd6, 0xc8, 0xbc, 0x87, 0x2, 0x3, 0x1, 0x0, 0x1, 0x2, 0x4, 0x28, 0x39, 0x64, 0x21, 0x2, 0x3, 0x0, 0xfa, 0x3f, 0x2, 0x3, 0x0, 0xdb, 0xb9, 0x2, 0x2, 0x50, 0xed, 0x2, 0x3, 0x0, 0xa6, 0x49, 0x2, 0x2, 0x1d, 0xb0}
	pkcs8EC = []byte{0x30, 0x78, 0x2, 0x1, 0x0, 0x30, 0x10, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x5, 0x2b, 0x81, 0x4, 0x0, 0x21, 0x4, 0x61, 0x30, 0x5f, 0x2, 0x1, 0x1, 0x4, 0x1c, 0x61, 0x59, 0x5b, 0x81, 0x6d, 0x58, 0x8d, 0x96, 0x33, 0xeb, 0xc0, 0xbd, 0xb1, 0x1f, 0xb6, 0x12, 0xd3, 0xb3, 0x7c, 0x9b, 0x7e, 0xd5, 0x15, 0xf0, 0xa0, 0xc0, 0xc9, 0x48, 0xa1, 0x3c, 0x3, 0x3a, 0x0, 0x4, 0xaa, 0x42, 0xa9, 0x6b, 0xfe, 0xbc, 0x85, 0x49, 0xcb, 0x96, 0xe4, 0x15, 0x11, 0x8, 0xf, 0xdf, 0x16, 0x4a, 0x15, 0xb0, 0x9b, 0x33, 0x64, 0x33, 0x6c, 0x8e, 0xbc, 0x87, 0xaf, 0x1f, 0x79, 0xfe, 0xc2, 0xd3, 0x86, 0xa9, 0x12, 0xc4, 0x4e, 0x32, 0x5d, 0xaa, 0x7c, 0xfc, 0x8b, 0xed, 0x4f, 0xd2, 0xa, 0x10, 0xe1, 0xae, 0x0, 0x3a, 0xde, 0x41}
	pub     = rsa.PublicKey{N: big.NewInt(3603479687), E: 65537}
	pkix    = []byte{0x30, 0x20, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1, 0x5, 0x0, 0x3, 0xf, 0x0, 0x30, 0xc, 0x2, 0x5, 0x0, 0xd6, 0xc8, 0xbc, 0x87, 0x2, 0x3, 0x1, 0x0, 0x1}
	pkixEC  = []byte{0x30, 0x4e, 0x30, 0x10, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x5, 0x2b, 0x81, 0x4, 0x0, 0x21, 0x3, 0x3a, 0x0, 0x4, 0x92, 0x6a, 0x93, 0xf0, 0x42, 0xec, 0x1b, 0x46, 0x95, 0x47, 0xd4, 0x0, 0xfa, 0x45, 0x83, 0x39, 0x8, 0x1e, 0xe8, 0x2b, 0xb7, 0xbc, 0x6c, 0xd7, 0x96, 0x80, 0xc, 0x2d, 0xb6, 0xc1, 0x5c, 0x33, 0x14, 0x44, 0xb7, 0xc, 0xc5, 0x98, 0x4b, 0x7a, 0xf2, 0x55, 0x9, 0x22, 0xac, 0x5c, 0x67, 0xd8, 0x46, 0xb2, 0x42, 0xc9, 0x9f, 0xfc, 0x6f, 0x4d}
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
		{"PKCS1 key", args{pkcs1, "key_id"}, Settings{priv, "key_id", ""}, false},
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
		{"PKCS1 key", args{pkcs1, "key_id", "key_url"}, Settings{priv, "key_id", "key_url"}, false},
		{"PKCS8 key", args{pkcs8, "key_id", "key_url"}, Settings{priv, "key_id", "key_url"}, false},
		{"Invalid", args{[]byte("invalid key"), "key_id", "key_url"}, Settings{}, true},
		{"PKCS8 EC key", args{pkcs8EC, "key_id", "key_url"}, Settings{}, true},
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
		{"Normal", &Provider{keys: make(map[string]*rsa.PublicKey)}, args{publickey.New(pkix, "key_id")}, false},
		{"Already exists", &Provider{keys: map[string]*rsa.PublicKey{"key_id": &pub}}, args{publickey.New(pkix, "key_id")}, true},
		{"Invalid", &Provider{keys: make(map[string]*rsa.PublicKey)}, args{publickey.New([]byte("invalid key"), "key_id")}, true},
		{"PKIX RSA key", &Provider{keys: make(map[string]*rsa.PublicKey)}, args{publickey.New(pkixEC, "key_id")}, true},
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
		{"Normal", &Provider{settings: Settings{kid: "signing_key"}, keys: make(map[string]*rsa.PublicKey)}, "key_id"},
		{"Same as signing key", &Provider{settings: Settings{kid: "signing_key"}, keys: make(map[string]*rsa.PublicKey)}, "signing_key"},
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
