package jwt

import (
	"errors"
	"reflect"
	"testing"
)

func TestJWT_Valid(t *testing.T) {
	tests := []struct {
		name string
		jwt  JWT
		want bool
	}{
		{"Normal", JWT{Header{Typ: "JWT"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), nil}, true},
		{"Error", JWT{Header{Typ: "JWT"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), errors.New("test error")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.jwt.Valid(); got != tt.want {
				t.Errorf("JWT.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJWT_ValidationError(t *testing.T) {
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
			if err := tt.jwt.ValidationError(); (err != nil) != tt.wantErr {
				t.Errorf("JWT.ValidationError() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHeader_getAlgorithm(t *testing.T) {
	alg := TestAlgorithm("test")
	SetAlgorithm("test", alg)
	SetSigningAlgorithm("test") // nolint:errcheck
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.jwt.validate(tt.args.data, tt.args.signature); (err != nil) != tt.wantErr {
				t.Errorf("JWT.validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type testValidationProvider byte

func (_ testValidationProvider) Validate(c []byte) error {
	if c[0] == 0xFF {
		return errors.New("test error")
	}
	return nil
}

func TestValidation(t *testing.T) {
	alg := TestAlgorithm("test")
	SetAlgorithm("test", alg)
	SetSigningAlgorithm("test") // nolint:errcheck

	token := JWT{Header{Typ: "JWT", Alg: "test"}, []byte{0x00}, nil}
	failToken := JWT{Header{Typ: "JWT", Alg: "test"}, []byte{0xFF}, nil}
	data := []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ")
	sig := []byte("testeyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ")

	AddValidationProvider("test", testValidationProvider(0x0)) // nolint:errcheck

	err := token.validate(data, sig)
	if err != nil {
		t.Errorf("did not expect error on JWT.validate() but got %s", err.Error())
	}
	err = failToken.validate(data, sig)
	if err == nil {
		t.Error("did expect error on JWT.validate() but got none")
	}
}
