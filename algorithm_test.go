package jwt

import (
	"errors"
	"testing"
)

// Defining an algorithm for testing

type TestAlgorithm string

func (alg TestAlgorithm) Sign(data []byte) ([]byte, error) {
	if string(alg) == "error" {
		return nil, errors.New("Here's the error you requested")
	}
	return append([]byte(alg), data...), nil
}

func (alg TestAlgorithm) Verify(data, hash []byte, h Header) error {
	if len(hash) == len(data)+len(alg) {
		return nil
	}
	return errors.New("token invalid")
}

func (alg TestAlgorithm) Header(h *Header) {
	h.Alg = string(alg)
}

func TestRegisterAlgorithm(t *testing.T) {
	type args struct {
		name string
		alg  SignatureProvider
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Normal", args{"test", TestAlgorithm("test1")}, false},
		{"Already exists", args{"test", TestAlgorithm("test2")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := AddSignatureProvider(tt.args.name, tt.args.alg); (err != nil) != tt.wantErr {
				t.Errorf("RegisterAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
			}
			if a, ok := signatureProviders[tt.args.name]; !tt.wantErr && (!ok || a != tt.args.alg) {
				t.Errorf("RegisterAlgorithm() failed - want %v but got %v", tt.args.alg, a)
			}
		})
	}
}

func TestSetAlgorithm(t *testing.T) {
	type args struct {
		name string
		alg  SignatureProvider
	}
	tests := []struct {
		name string
		args args
	}{
		{"Normal", args{"test", TestAlgorithm("test")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetSignatureProvider(tt.args.name, tt.args.alg)
			if a, ok := signatureProviders[tt.args.name]; !ok || a != tt.args.alg {
				t.Errorf("SetAlgorithm() failed - want %v but got %v", tt.args.alg, a)
			}
		})
	}
}

func TestDefaultAlgorithm(t *testing.T) {
	SetSignatureProvider("test", TestAlgorithm("test"))
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Normal", args{"test"}, false},
		{"Invalid", args{"sample"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SetSigningAlgorithm(tt.args.name); (err != nil) != tt.wantErr {
				t.Errorf("DefaultAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && defaultAlgorithm != tt.args.name {
				t.Errorf("DefaultAlgorithm() failed - want %v but got %v", tt.args.name, defaultAlgorithm)
			}
		})
	}
}
