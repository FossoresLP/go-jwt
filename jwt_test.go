package jwt

import (
	"testing"
)

func TestAddValidationProvider(t *testing.T) {
	type args struct {
		name     string
		provider ContentValidationProvider
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Normal", args{"test", testValidationProvider(0x0)}, false},
		{"Already exists", args{"test", testValidationProvider(0x0)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := AddValidationProvider(tt.args.name, tt.args.provider); (err != nil) != tt.wantErr {
				t.Errorf("AddValidationProvider() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRemoveValidationProvider(t *testing.T) {
	tests := []struct {
		name  string
		pname string
	}{
		{"Normal", "test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RemoveValidationProvider(tt.pname)
		})
	}
}

func TestRemoveSignatureProvider(t *testing.T) {
	tests := []struct {
		name  string
		pname string
	}{
		{"Normal", "test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RemoveSignatureProvider(tt.pname)
		})
	}
}
