package rs

import (
	"crypto/rsa"
	"math/big"
	"reflect"
	"testing"

	"github.com/fossoreslp/go-jwt/jwk"
)

var (
	priv       = &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(3603479687), E: 65537}, D: big.NewInt(674849825), Primes: []*big.Int{big.NewInt(64063), big.NewInt(56249)}, Precomputed: rsa.PrecomputedValues{Dp: big.NewInt(20717), Dq: big.NewInt(42569), Qinv: big.NewInt(7600), CRTValues: []rsa.CRTValue{}}}
	rsaPrivJWK = jwk.NewRSAPrivateKey(priv, "key_id")
	pub        = rsa.PublicKey{N: big.NewInt(3603479687), E: 65537}
	rsaPubJWK  = jwk.NewRSAPublicKey(&pub, "key_id")
	invalidJWK = jwk.JWK{}
)

func TestNewSettings(t *testing.T) {
	tests := []struct {
		name    string
		key     jwk.JWK
		want    Settings
		wantErr bool
	}{
		{"Normal", rsaPrivJWK, Settings{priv, "key_id", ""}, false},
		{"Invalid", invalidJWK, Settings{}, true},
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
		{"Normal", args{rsaPrivJWK, "key_url"}, Settings{priv, "key_id", "key_url"}, false},
		{"Invalid", args{invalidJWK, "key_url"}, Settings{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSettingsWithKeyURL(tt.args.key, tt.args.keyurl)
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
		key     jwk.JWK
		wantErr bool
	}{
		{"Normal", &Provider{keys: make(map[string]*rsa.PublicKey)}, rsaPubJWK, false},
		{"Already exists", &Provider{keys: map[string]*rsa.PublicKey{"key_id": &pub}}, rsaPubJWK, true},
		{"Invalid", &Provider{keys: make(map[string]*rsa.PublicKey)}, invalidJWK, true},
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
		want jwk.JWK
	}{
		{"Normal", Provider{settings: Settings{private: priv, kid: "key_id"}}, rsaPubJWK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.CurrentKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Provider.CurrentKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
