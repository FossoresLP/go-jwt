package jwt

import (
	"encoding/json"
	"errors"
	"time"
)

// ExpiresValidationProvider can be used to validate that the token is currently valid.
// It can be initialized with a tolerance that can compensate for slight differences in clocks.
type ExpiresValidationProvider struct {
	Tolerance int64
}

// Validate will be called during validation of a token
func (p ExpiresValidationProvider) Validate(c []byte) error {
	var exp struct {
		Expires int64 `json:"exp"`
	}

	if err := json.Unmarshal(c, &exp); err != nil {
		return err
	}

	if time.Unix(exp.Expires+p.Tolerance, 0).Before(time.Now().UTC()) {
		return errors.New("jwt has expired")
	}

	return nil
}

// NotBeforeValidationProvider can be used to validate that the token is currently valid.
// It can be initialized with a tolerance that can compensate for slight differences in clocks.
type NotBeforeValidationProvider struct {
	Tolerance int64
}

// Validate will be called during validation of a token
func (p NotBeforeValidationProvider) Validate(c []byte) error {
	var nbf struct {
		NotBefore int64 `json:"nbf"`
	}

	if err := json.Unmarshal(c, &nbf); err != nil {
		return err
	}

	if time.Unix(nbf.NotBefore-p.Tolerance, 0).After(time.Now().UTC()) {
		return errors.New("jwt is not valid, yet")
	}

	return nil
}

// IssuedAtValidationProvider can be used that the token has been issued in a specific timeframe.
// It should be initialized with an amount of seconds after which tokens expire and optionally also a tolerance.
// Important: This provider also checks whether issued at timestamp is in the future and returns an error in that case.
type IssuedAtValidationProvider struct {
	Tolerance    int64
	ExpiresAfter int64
}

// Validate will be called during validation of a token
func (p IssuedAtValidationProvider) Validate(c []byte) error {
	var iat struct {
		IssuedAt int64 `json:"iat"`
	}

	if err := json.Unmarshal(c, &iat); err != nil {
		return err
	}

	if time.Unix(iat.IssuedAt+p.ExpiresAfter+p.Tolerance, 0).Before(time.Now().UTC()) {
		return errors.New("jwt has expired")
	}

	if time.Unix(iat.IssuedAt-p.Tolerance, 0).After(time.Now().UTC()) {
		return errors.New("jwt is not valid, yet")
	}

	return nil
}

// IssuerValidationProvider validates the issuer of a JWT.
// It should be initialized with a slice of issuers.
// By default it considers the slice a blacklist. This can be changed by setting whilelist to true.
type IssuerValidationProvider struct {
	Issuers   []string
	Whitelist bool
}

// Validate will be called during validation of a token
func (p IssuerValidationProvider) Validate(c []byte) error {
	var iss struct {
		Issuer string `json:"iss"`
	}

	if err := json.Unmarshal(c, &iss); err != nil {
		return err
	}

	if p.Whitelist {
		for _, issuer := range p.Issuers {
			if iss.Issuer == issuer {
				return nil
			}
		}
		return errors.New("issuer is not on whitelist")
	}

	for _, issuer := range p.Issuers {
		if iss.Issuer == issuer {
			return errors.New("issuer is on blacklist")
		}
	}
	return nil
}

// AudienceValidationProvider checks whether the token is for the correct audience.
// It should be initialized with an expected audience and will return an error when a different audience is encountered.
type AudienceValidationProvider struct {
	ExpectedAudience string
}

// Validate will be called during validation of a token
func (p AudienceValidationProvider) Validate(c []byte) error {
	var aud struct {
		Audience string `json:"aud"`
	}

	if err := json.Unmarshal(c, &aud); err != nil {
		return err
	}

	if p.ExpectedAudience == aud.Audience {
		return nil
	}
	return errors.New("invalid audience")
}

// TokenIDValidationProvider can be used to blacklist some tokens.
// It should be initialized with a slice of forbidden token IDs and will return an error when one of those IDs in encountered.
type TokenIDValidationProvider struct {
	ForbiddenTokenIDs []string
}

// Validate will be called during validation of a token
func (p TokenIDValidationProvider) Validate(c []byte) error {
	var jti struct {
		TokenID string `json:"jti"`
	}

	if err := json.Unmarshal(c, &jti); err != nil {
		return err
	}

	for _, id := range p.ForbiddenTokenIDs {
		if jti.TokenID == id {
			return errors.New("token ID is on blacklist")
		}
	}
	return nil
}
