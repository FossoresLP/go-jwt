package hs

import (
	"reflect"
	"testing"
)

func TestKeySet_SetKeys(t *testing.T) {
	type args struct {
		priv []byte
		pub  []byte
	}
	tests := []struct {
		name    string
		ks      *KeySet
		args    args
		wantErr bool
	}{
		{"Normal", &KeySet{}, args{[]byte("test"), nil}, false},
		{"Empty key", &KeySet{}, args{nil, nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.ks.SetKeys(tt.args.priv, tt.args.pub); (err != nil) != tt.wantErr {
				t.Errorf("KeySet.SetKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeySet_SetKeyID(t *testing.T) {
	tests := []struct {
		name string
		ks   *KeySet
		kid  string
	}{
		{"Normal", &KeySet{}, "key_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.ks.SetKeyID(tt.kid)
		})
	}
}

func TestKeySet_SetKeyURL(t *testing.T) {
	tests := []struct {
		name string
		ks   *KeySet
		jku  string
	}{
		{"Normal", &KeySet{}, "key_url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.ks.SetKeyURL(tt.jku)
		})
	}
}

func TestKeySet_GetPublicKey(t *testing.T) {
	tests := []struct {
		name string
		ks   KeySet
		want PublicKey
	}{
		{"Key only", KeySet{key: []byte("test")}, PublicKey{key: []byte("test")}},
		{"Key with ID", KeySet{key: []byte("test"), kid: "key_id"}, PublicKey{key: []byte("test"), kid: "key_id"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ks.GetPublicKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeySet.GetPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicKey_GetPublicKey(t *testing.T) {
	tests := []struct {
		name string
		s    PublicKey
		want []byte
	}{
		{"Normal", PublicKey{key: []byte("test")}, []byte("test")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.GetPublicKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PublicKey.GetPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicKey_GetKeyID(t *testing.T) {
	tests := []struct {
		name string
		s    PublicKey
		want string
	}{
		{"Normal", PublicKey{kid: "key_id"}, "key_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.GetKeyID(); got != tt.want {
				t.Errorf("PublicKey.GetKeyID() = %v, want %v", got, tt.want)
			}
		})
	}
}
