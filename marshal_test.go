package jwt

import (
	"reflect"
	"testing"
)

func TestJWT_MarshalText(t *testing.T) {
	SetAlgorithm("test", TestAlgorithm("test"))
	SetSigningAlgorithm("test") // nolint:errcheck
	tests := []struct {
		name    string
		jwt     JWT
		want    []byte
		wantErr bool
	}{
		{"Normal", JWT{Header{Typ: "JWT"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), nil}, []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ.dGVzdGV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSjBaWE4wSW4wLmV5SnVZVzFsSWpvaWRHVnpkQ0lzSW5WelpTSTZJblJsYzNScGJtY2lmUQ"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.jwt.MarshalText()
			if (err != nil) != tt.wantErr {
				t.Errorf("JWT.MarshalText() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("JWT.MarshalText() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJWT_UnmarshalText(t *testing.T) {
	SetAlgorithm("test", TestAlgorithm("test"))
	SetSigningAlgorithm("test") // nolint:errcheck
	type args struct {
		in []byte
	}
	tests := []struct {
		name    string
		jwt     *JWT
		args    args
		wantErr bool
	}{
		{"Normal", &JWT{}, args{[]byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ.dGVzdGV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSjBaWE4wSW4wLmV5SnVZVzFsSWpvaWRHVnpkQ0lzSW5WelpTSTZJblJsYzNScGJtY2lmUQ")}, false},
		{"InvalidToken", &JWT{}, args{[]byte("test")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.jwt.UnmarshalText(tt.args.in); (err != nil) != tt.wantErr {
				t.Errorf("JWT.UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(tt.jwt, &JWT{Header{Typ: "JWT", Alg: "test"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), nil}) {
				t.Errorf("JWT.UnmarshalText() = %+v, want %+v", tt.jwt, &JWT{Header{Typ: "JWT", Alg: "test"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), nil})
			}
		})
	}
}

func TestJWT_MarshalBinary(t *testing.T) {
	SetAlgorithm("test", TestAlgorithm("test"))
	SetSigningAlgorithm("test") // nolint:errcheck
	tests := []struct {
		name    string
		jwt     JWT
		want    []byte
		wantErr bool
	}{
		{"Normal", JWT{Header{Typ: "JWT"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), nil}, []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ.dGVzdGV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSjBaWE4wSW4wLmV5SnVZVzFsSWpvaWRHVnpkQ0lzSW5WelpTSTZJblJsYzNScGJtY2lmUQ"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.jwt.MarshalBinary()
			if (err != nil) != tt.wantErr {
				t.Errorf("JWT.MarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("JWT.MarshalBinary() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJWT_UnmarshalBinary(t *testing.T) {
	SetAlgorithm("test", TestAlgorithm("test"))
	SetSigningAlgorithm("test") // nolint:errcheck
	type args struct {
		in []byte
	}
	tests := []struct {
		name    string
		jwt     *JWT
		args    args
		wantErr bool
	}{
		{"Normal", &JWT{}, args{[]byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ.dGVzdGV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSjBaWE4wSW4wLmV5SnVZVzFsSWpvaWRHVnpkQ0lzSW5WelpTSTZJblJsYzNScGJtY2lmUQ")}, false},
		{"InvalidToken", &JWT{}, args{[]byte("test")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.jwt.UnmarshalBinary(tt.args.in); (err != nil) != tt.wantErr {
				t.Errorf("JWT.UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(tt.jwt, &JWT{Header{Typ: "JWT", Alg: "test"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), nil}) {
				t.Errorf("JWT.UnmarshalText() = %+v, want %+v", tt.jwt, &JWT{Header{Typ: "JWT", Alg: "test"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), nil})
			}
		})
	}
}
