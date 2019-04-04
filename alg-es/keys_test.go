package es

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"reflect"
	"testing"

	"github.com/fossoreslp/go-jwt/jwk"
)

var (
	x, _         = new(big.Int).SetString("53362156244743717582302245396579768295291970453913383836603205696230085410059", 10)
	y, _         = new(big.Int).SetString("30291755020966801726600908749968268600863491590438969900821061765762053214603", 10)
	d, _         = new(big.Int).SetString("81441865675641311106028598596990373907775388393469674002729224480451685045463", 10)
	priv         = &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	pub          = ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	ecPrivJWK, _ = jwk.NewECPrivateKey(priv, "key_id")
	ecPubJWK, _  = jwk.NewECPublicKey(&pub, "key_id")
	invalidJWK   = jwk.NewBasic(nil, "key_id")
)

func TestNewSettings(t *testing.T) {
	tests := []struct {
		name    string
		key     jwk.JWK
		want    Settings
		wantErr bool
	}{
		{"EC key", ecPrivJWK, Settings{priv, "key_id", ""}, false},
		{"Invalid", invalidJWK, Settings{priv, "key_id", ""}, false},
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
		{"EC key", args{ecPrivJWK, "key_url"}, Settings{priv, "key_id", "key_url"}, false},
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
		{"Normal", &Provider{keys: make(map[string]*ecdsa.PublicKey)}, ecPubJWK, false},
		{"Already exists", &Provider{keys: map[string]*ecdsa.PublicKey{"key_id": &pub}}, ecPubJWK, true},
		{"Invalid", &Provider{keys: make(map[string]*ecdsa.PublicKey)}, invalidJWK, true},
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
		want jwk.JWK
	}{
		{"Normal", Provider{settings: Settings{private: priv, kid: "key_id"}}, ecPubJWK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.CurrentKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Provider.CurrentKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
