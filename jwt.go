package jwt

import (
	"errors"
)

var (
	signatureProviders  map[string]SignatureProvider
	defaultAlgorithm    string
	validationProviders map[string]ContentValidationProvider
)

func init() {
	signatureProviders = make(map[string]SignatureProvider)
	validationProviders = make(map[string]ContentValidationProvider)
}

// AddSignatureProvider tries to add the signature provider to the list but fails when one with the same name already exists.
func AddSignatureProvider(name string, provider SignatureProvider) error {
	if _, ok := signatureProviders[name]; ok {
		return errors.New("algorithm already registered: use SetSignatureProvider to force replacement")
	}
	signatureProviders[name] = provider
	return nil
}

// SetSignatureProvider sets the signature provider ignoring previous settings for the same name.
func SetSignatureProvider(name string, provider SignatureProvider) {
	signatureProviders[name] = provider
}

// RemoveSignatureProvider removes a signature provider by name
func RemoveSignatureProvider(name string) {
	delete(signatureProviders, name)
}

// SetSigningAlgorithm sets the default algorithm that will be used with Encode and by the Marshalers for encoding
func SetSigningAlgorithm(name string) error {
	if _, ok := signatureProviders[name]; !ok {
		return errors.New("algorithm does not exist")
	}
	defaultAlgorithm = name
	return nil
}

// AddValidationProvider adds a content validation provider
func AddValidationProvider(name string, provider ContentValidationProvider) error {
	if _, ok := validationProviders[name]; ok {
		return errors.New("there is already a content validation provider with this name")
	}
	validationProviders[name] = provider
	return nil
}

// RemoveValidationProvider removes a content validation provider by name
func RemoveValidationProvider(name string) {
	delete(validationProviders, name)
}
