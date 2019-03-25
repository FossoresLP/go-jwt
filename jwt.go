package jwt

import (
	"errors"
)

var (
	algorithms          map[string]Algorithm
	defaultAlgorithm    string
	validationProviders map[string]VerificationProvider
)

func init() {
	algorithms = make(map[string]Algorithm)
	validationProviders = make(map[string]VerificationProvider)
}

// RegisterAlgorithm tries to add the algorithm to the list but fails when one with the same name already exists.
func RegisterAlgorithm(name string, alg Algorithm) error {
	if _, ok := algorithms[name]; ok {
		return errors.New("algorithm already registered: use SetAlgorithm to force replacement")
	}
	algorithms[name] = alg
	return nil
}

// SetAlgorithm sets the algorithm ignoring previous settings for the name.
func SetAlgorithm(name string, alg Algorithm) {
	algorithms[name] = alg
}

// DefaultAlgorithm sets the default algorithm that will be used with Encode and by the Marshalers for encoding
func DefaultAlgorithm(name string) error {
	if _, ok := algorithms[name]; !ok {
		return errors.New("algorithm does not exist")
	}
	defaultAlgorithm = name
	return nil
}

func AddValidationProvider(name string, provider VerificationProvider) error {
	if _, ok := validationProviders[name]; ok {
		return errors.New("there is already a validation function with this name registered")
	}
	validationProviders[name] = provider
	return nil
}

func RemoveValidationProvider(name string) {
	delete(validationProviders, name)
}
