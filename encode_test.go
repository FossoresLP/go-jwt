package jwt

import (
	"reflect"
	"testing"
)

func Test_join(t *testing.T) {
	type args struct {
		b [][]byte
	}
	tests := []struct {
		name       string
		args       args
		wantResult []byte
	}{
		{"Zero", args{nil}, nil},
		{"Single", args{[][]byte{[]byte("test")}}, []byte("test")},
		{"Two", args{[][]byte{[]byte("test1"), []byte("test2")}}, []byte("test1.test2")},
		{"Three", args{[][]byte{[]byte("test1"), []byte("test2"), []byte("test3")}}, []byte("test1.test2.test3")},
		{"Empty", args{[][]byte{[]byte("test1"), []byte(""), []byte("test3")}}, []byte("test1..test3")},
		{"Empty_Beginning", args{[][]byte{[]byte(""), []byte("test2"), []byte("test3")}}, []byte(".test2.test3")},
		{"Empty_End", args{[][]byte{[]byte("test1"), []byte("test2"), []byte("")}}, []byte("test1.test2.")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotResult := join(tt.args.b...); !reflect.DeepEqual(gotResult, tt.wantResult) {
				t.Errorf("join() = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}

func Test_b64encode(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		wantOut []byte
	}{
		{"Data", args{[]byte("{\"testing\": \"JSON\", \"with\": 3.0, \"elements\": true}")}, []byte("eyJ0ZXN0aW5nIjogIkpTT04iLCAid2l0aCI6IDMuMCwgImVsZW1lbnRzIjogdHJ1ZX0")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotOut := b64encode(tt.args.data); !reflect.DeepEqual(gotOut, tt.wantOut) {
				t.Errorf("b64encode() = %v, want %v", gotOut, tt.wantOut)
			}
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want JWT
	}{
		{"Normal", []byte("Test"), JWT{Header{Typ: "JWT"}, []byte("Test"), nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.data); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_encodeHeader(t *testing.T) {
	tests := []struct {
		name string
		h    Header
		want []byte
	}{
		{"Normal", Header{Typ: "JWT", Alg: "EdDSA"}, []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9")},
		{"WithKeyID", Header{Typ: "JWT", Alg: "EdDSA", Kid: "unique_key_id"}, []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6InVuaXF1ZV9rZXlfaWQifQ")},
		{"WithKeyURL", Header{Typ: "JWT", Alg: "EdDSA", Jku: "https://example.com/get_key"}, []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImprdSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZ2V0X2tleSJ9")},
		{"WithKeyIDAndURL", Header{Typ: "JWT", Alg: "EdDSA", Kid: "unique_key_id", Jku: "https://example.com/get_key"}, []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6InVuaXF1ZV9rZXlfaWQiLCJqa3UiOiJodHRwczovL2V4YW1wbGUuY29tL2dldF9rZXkifQ")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodeHeader(tt.h); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encodeHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJWT_Encode(t *testing.T) {
	tests := []struct {
		name       string
		t          JWT
		alg        SignatureProvider
		wantResult []byte
		wantErr    bool
	}{
		{"Normal", JWT{Header{Typ: "JWT"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), nil}, TestAlgorithm("test"), []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ.dGVzdGV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSjBaWE4wSW4wLmV5SnVZVzFsSWpvaWRHVnpkQ0lzSW5WelpTSTZJblJsYzNScGJtY2lmUQ"), false},
		{"Fail", JWT{Header{Typ: "JWT"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), nil}, TestAlgorithm("error"), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetSignatureProvider("test", tt.alg)
			SetSigningAlgorithm("test") // nolint:errcheck
			gotResult, err := tt.t.Encode()
			if (err != nil) != tt.wantErr {
				t.Errorf("JWT.Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResult, tt.wantResult) {
				t.Errorf("JWT.Encode() = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}

func TestJWT_Encode_Edgecases(t *testing.T) {
	defaultAlgorithm = ""
	_, err := JWT{Header{Typ: "JWT"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), nil}.Encode()
	if err == nil {
		t.Error("JWT.Encode() should fail when default algorithm is not set")
	}

	defaultAlgorithm = "sample"
	_, err = JWT{Header{Typ: "JWT"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), nil}.Encode()
	if err == nil {
		t.Error("JWT.Encode() should fail when default algorithm does not exist")
	}
}
