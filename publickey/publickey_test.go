package publickey

import (
	"reflect"
	"testing"
)

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

func TestNew(t *testing.T) {
	type args struct {
		key []byte
		id  string
	}
	tests := []struct {
		name string
		args args
		want PublicKey
	}{
		{"Normal", args{[]byte("test"), "key_id"}, PublicKey{key: []byte("test"), kid: "key_id"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.key, tt.args.id); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}
