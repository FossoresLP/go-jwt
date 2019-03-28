package jwt

import (
	"fmt"
)

// Valid returns whether the token is valid or not
func (jwt JWT) Valid() bool {
	return jwt.validationError == nil
}

// ValidationError returns the error that occurred during validation or nil
func (jwt JWT) ValidationError() error {
	return jwt.validationError
}

func (jwt JWT) validate(data, signature []byte) error {
	alg, err := jwt.Header.getAlgorithm()
	if err != nil {
		return err
	}

	// Check the hash using the Verify function of the algorithm declared by the header
	if err := alg.Verify(data, signature, jwt.Header); err != nil {
		return err
	}

	for _, p := range validationProviders {
		if err := p.Validate(jwt.Content); err != nil {
			return err
		}
	}
	return nil
}

func (h Header) getAlgorithm() (SignatureProvider, error) {
	a, ok := signatureProviders[h.Alg]
	if !ok {
		return nil, fmt.Errorf("algorithm %s is not supported", h.Alg)
	}
	return a, nil
}
