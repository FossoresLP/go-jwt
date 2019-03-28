package jwt

import (
	"reflect"
	"testing"
)

func TestDecode(t *testing.T) {
	SetAlgorithm("test", TestAlgorithm("test"))
	SetSigningAlgorithm("test") // nolint:errcheck
	tests := []struct {
		name     string
		token    []byte
		wantData JWT
		wantErr  bool
	}{
		{"Normal", []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.eyJuYW1lIjoidGVzdCIsInVzZSI6InRlc3RpbmcifQ.dGVzdGV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSjBaWE4wSW4wLmV5SnVZVzFsSWpvaWRHVnpkQ0lzSW5WelpTSTZJblJsYzNScGJtY2lmUQ"), JWT{Header{Typ: "JWT", Alg: "test"}, []byte("{\"name\":\"test\",\"use\":\"testing\"}"), nil}, false},
		{"TwoSections", []byte("A.B"), JWT{}, true},
		{"OneSection", []byte("A"), JWT{}, true},
		{"FourSections", []byte("A.B.C.D"), JWT{}, true},
		{"HeaderInvalidBase64", []byte("A._._"), JWT{}, true},
		{"HeaderInvalidJSON", []byte("YQ._._"), JWT{}, true},
		{"TokenNotJWT", []byte("eyJ0eXAiOiJub25lIiwiYWxnIjoibm9uZSJ9._._"), JWT{}, true},
		{"ContentInvalidBase64", []byte("eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJlZDI1NTE5In0.A._"), JWT{}, true},
		{"HashInvalidBase64", []byte("eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJlZDI1NTE5In0.IkhlbGxvIHdvcmxkISI.A"), JWT{}, true},
		{"HashEmpty", []byte("eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJlZDI1NTE5In0.IkhlbGxvIHdvcmxkISI."), JWT{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotData, err := Decode(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(gotData, tt.wantData) {
				t.Errorf("Decode() = %v, want %v", gotData, tt.wantData)
			}
		})
	}
}
