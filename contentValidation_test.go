package jwt

import "testing"

func TestExpiresValidationProvider_Validate(t *testing.T) {
	tests := []struct {
		name    string
		p       ExpiresValidationProvider
		c       []byte
		wantErr bool
	}{
		{"Normal", ExpiresValidationProvider{0}, []byte(`{"exp": 9999999999}`), false},
		{"Expired", ExpiresValidationProvider{0}, []byte(`{"exp": 0}`), true},
		{"Invalid JSON", ExpiresValidationProvider{0}, []byte(`hello world`), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.Validate(tt.c); (err != nil) != tt.wantErr {
				t.Errorf("ExpiresValidationProvider.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNotBeforeValidationProvider_Validate(t *testing.T) {
	tests := []struct {
		name    string
		p       NotBeforeValidationProvider
		c       []byte
		wantErr bool
	}{
		{"Normal", NotBeforeValidationProvider{0}, []byte(`{"nbf": 0}`), false},
		{"Not valid, yet", NotBeforeValidationProvider{0}, []byte(`{"nbf": 9999999999}`), true},
		{"Invalid JSON", NotBeforeValidationProvider{0}, []byte(`hello world`), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.Validate(tt.c); (err != nil) != tt.wantErr {
				t.Errorf("NotBeforeValidationProvider.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIssuedAtValidationProvider_Validate(t *testing.T) {
	tests := []struct {
		name    string
		p       IssuedAtValidationProvider
		c       []byte
		wantErr bool
	}{
		{"Normal", IssuedAtValidationProvider{0, 9999999999}, []byte(`{"iat": 0}`), false},
		{"Expired", IssuedAtValidationProvider{0, 0}, []byte(`{"iat": 0}`), true},
		{"Not valid, yet", IssuedAtValidationProvider{0, 0}, []byte(`{"iat": 9999999999}`), true},
		{"Invalid JSON", IssuedAtValidationProvider{0, 0}, []byte(`hello world`), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.Validate(tt.c); (err != nil) != tt.wantErr {
				t.Errorf("IssuedAtValidationProvider.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIssuerValidationProvider_Validate(t *testing.T) {
	tests := []struct {
		name    string
		p       IssuerValidationProvider
		c       []byte
		wantErr bool
	}{
		{"Blacklist success", IssuerValidationProvider{nil, false}, []byte(`{"iss": "issuer_id"}`), false},
		{"Blacklist fail", IssuerValidationProvider{[]string{"issuer_id"}, false}, []byte(`{"iss": "issuer_id"}`), true},
		{"Whitelist success", IssuerValidationProvider{[]string{"issuer_id"}, true}, []byte(`{"iss": "issuer_id"}`), false},
		{"Whitelist fail", IssuerValidationProvider{nil, true}, []byte(`{"iss": "issuer_id"}`), true},
		{"Invalid JSON", IssuerValidationProvider{nil, false}, []byte(`hello world`), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.Validate(tt.c); (err != nil) != tt.wantErr {
				t.Errorf("IssuerValidationProvider.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAudienceValidationProvider_Validate(t *testing.T) {
	tests := []struct {
		name    string
		p       AudienceValidationProvider
		c       []byte
		wantErr bool
	}{
		{"Normal", AudienceValidationProvider{"audience"}, []byte(`{"aud": "audience"}`), false},
		{"Invalid audience", AudienceValidationProvider{"audience"}, []byte(`{"aud": "not audience"}`), true},
		{"Invalid JSON", AudienceValidationProvider{""}, []byte(`hello world`), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.Validate(tt.c); (err != nil) != tt.wantErr {
				t.Errorf("AudienceValidationProvider.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenIDValidationProvider_Validate(t *testing.T) {
	tests := []struct {
		name    string
		p       TokenIDValidationProvider
		c       []byte
		wantErr bool
	}{
		{"Normal", TokenIDValidationProvider{nil}, []byte(`{"jti": "token_id"}`), false},
		{"Blacklisted", TokenIDValidationProvider{[]string{"token_id"}}, []byte(`{"jti": "token_id"}`), true},
		{"Invalid JSON", TokenIDValidationProvider{nil}, []byte(`hello world`), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.Validate(tt.c); (err != nil) != tt.wantErr {
				t.Errorf("TokenIDValidationProvider.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
