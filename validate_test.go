package jwt

import (
	"errors"
	"reflect"
	"testing"
)

func TestJWT_Validate(t *testing.T) {
	tests := []struct {
		name    string
		jwt     JWT
		wantErr bool
	}{
		{"Normal", JWT{Header{Typ: "JWT"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), nil}, false},
		{"Error", JWT{Header{Typ: "JWT"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), errors.New("test error")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.jwt.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("JWT.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestHeader_getAlgorithm(t *testing.T) {
	alg := TestAlgorithm("test")
	SetAlgorithm("test", alg)
	DefaultAlgorithm("test")
	tests := []struct {
		name    string
		h       Header
		want    Algorithm
		wantErr bool
	}{
		{"Normal", Header{Typ: "JWT", Alg: "test"}, alg, false},
		{"Algorithm missing", Header{Typ: "JWT", Alg: "sample"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.getAlgorithm()
			if (err != nil) != tt.wantErr {
				t.Errorf("Header.getAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Header.getAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_checkTimestamps(t *testing.T) {
	tests := []struct {
		name    string
		c       []byte
		wantErr bool
	}{
		{"Normal", []byte(`{"nbf": 1, "exp": 999999999999}`), false},
		{"Invalid JSON", []byte(`{"test": {,}`), false}, // Invalid JSON does not cause an error
		{"NotBefore", []byte(`{"nbf": 999999999999}`), true},
		{"Expires", []byte(`{"exp": 1}`), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkTimestamps(tt.c); (err != nil) != tt.wantErr {
				t.Errorf("checkTimestamps() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestJWT_validate(t *testing.T) {
	type args struct {
		data      []byte
		signature []byte
	}
	tests := []struct {
		name    string
		jwt     JWT
		args    args
		wantErr bool
	}{
		{"Normal", JWT{Header{Typ: "JWT", Alg: "test"}, nil, nil}, args{[]byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ"), []byte("testeyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ")}, false},
		{"Unkown algorithm", JWT{Header{Typ: "JWT", Alg: "sample"}, nil, nil}, args{nil, nil}, true},
		{"Invalid hash", JWT{Header{Typ: "JWT", Alg: "test"}, nil, nil}, args{[]byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ"), nil}, true},
		{"Invalid Expires", JWT{Header{Typ: "JWT", Alg: "test"}, []byte(`{"exp":1}`), nil}, args{[]byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJleHAiOjF9"), []byte("testeyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJleHAiOjF9")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.jwt.validate(tt.args.data, tt.args.signature); (err != nil) != tt.wantErr {
				t.Errorf("JWT.validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
