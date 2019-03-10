package eddsa

import (
	"reflect"
	"testing"

	"github.com/fossoreslp/go-jwt/publickey"
)

func TestEd25519KeySet_SetKeys(t *testing.T) {
	type args struct {
		priv []byte
		pub  []byte
	}
	tests := []struct {
		name    string
		ks      *Ed25519KeySet
		args    args
		wantErr bool
	}{
		{"Normal", &Ed25519KeySet{}, args{[]byte("This byte slice has a length of 64bytes for use as a private key"), []byte("This public key has only 32bytes")}, false},
		{"No private key", &Ed25519KeySet{}, args{nil, []byte("This public key has only 32bytes")}, false},
		{"No public key", &Ed25519KeySet{}, args{[]byte("This byte slice has a length of 64bytes for use as a private key"), nil}, false},
		{"No keys", &Ed25519KeySet{}, args{nil, nil}, false},
		{"Invalid length private key", &Ed25519KeySet{}, args{[]byte("This is too short"), nil}, true},
		{"Invalid length public key", &Ed25519KeySet{}, args{nil, []byte("This one, too")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.ks.SetKeys(tt.args.priv, tt.args.pub); (err != nil) != tt.wantErr {
				t.Errorf("Ed25519KeySet.SetKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEd448KeySet_SetKeys(t *testing.T) {
	type args struct {
		priv []byte
		pub  []byte
	}
	tests := []struct {
		name    string
		ks      *Ed448KeySet
		args    args
		wantErr bool
	}{
		{"Normal", &Ed448KeySet{}, args{[]byte("This byte slice has a length of 144 bytes meant for use as an Ed448 private key. It is longer but that makes the algorithm stronger than Ed25519"), []byte("The public key now has 56 bytes, a lot more than before.")}, false},
		{"No private key", &Ed448KeySet{}, args{nil, []byte("The public key now has 56 bytes, a lot more than before.")}, false},
		{"No public key", &Ed448KeySet{}, args{[]byte("This byte slice has a length of 144 bytes meant for use as an Ed448 private key. It is longer but that makes the algorithm stronger than Ed25519"), nil}, false},
		{"No keys", &Ed448KeySet{}, args{nil, nil}, false},
		{"Invalid length private key", &Ed448KeySet{}, args{[]byte("This is too short"), nil}, true},
		{"Invalid length public key", &Ed448KeySet{}, args{nil, []byte("This one, too")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.ks.SetKeys(tt.args.priv, tt.args.pub); (err != nil) != tt.wantErr {
				t.Errorf("Ed448KeySet.SetKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEd25519KeySet_SetKeyID(t *testing.T) {
	tests := []struct {
		name string
		ks   *Ed25519KeySet
		kid  string
	}{
		{"Normal", &Ed25519KeySet{}, "key_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.ks.SetKeyID(tt.kid)
		})
	}
}

func TestEd448KeySet_SetKeyID(t *testing.T) {
	tests := []struct {
		name string
		ks   *Ed448KeySet
		kid  string
	}{
		{"Normal", &Ed448KeySet{}, "key_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.ks.SetKeyID(tt.kid)
		})
	}
}

func TestEd25519KeySet_SetKeyURL(t *testing.T) {
	tests := []struct {
		name string
		ks   *Ed25519KeySet
		jku  string
	}{
		{"Normal", &Ed25519KeySet{}, "key_url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.ks.SetKeyURL(tt.jku)
		})
	}
}

func TestEd448KeySet_SetKeyURL(t *testing.T) {
	tests := []struct {
		name string
		ks   *Ed448KeySet
		jku  string
	}{
		{"Normal", &Ed448KeySet{}, "key_url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.ks.SetKeyURL(tt.jku)
		})
	}
}

func TestEd25519KeySet_GetPublicKey(t *testing.T) {
	keyArray := [32]byte{0xFF}
	tests := []struct {
		name string
		ks   Ed25519KeySet
		want publickey.PublicKey
	}{
		{"Normal", Ed25519KeySet{public: keyArray[:], kid: "key_id"}, publickey.New(keyArray[:], "key_id")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ks.GetPublicKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Ed25519KeySet.GetPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEd448KeySet_GetPublicKey(t *testing.T) {
	keyArray := [56]byte{0xFF}
	tests := []struct {
		name string
		ks   Ed448KeySet
		want publickey.PublicKey
	}{
		{"Normal", Ed448KeySet{public: keyArray, kid: "key_id"}, publickey.New(keyArray[:], "key_id")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ks.GetPublicKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Ed448KeySet.GetPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
