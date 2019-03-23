package eddsa

import (
	"errors"

	"golang.org/x/crypto/ed25519"
)

// Settings stores the signature settings for an EdDSA curve
type Settings struct {
	typ     int
	ed25519 ed25519.PrivateKey
	ed448   [144]byte
	kid     string
	jku     string
}

// NewSettings creates new signature settings for the parameters
func NewSettings(key []byte, keyid string) (Settings, error) {
	return NewSettingsWithKeyID(key, keyid, "")
}

// NewSettingsWithKeyID creates new signature settings for the parameters
func NewSettingsWithKeyID(key []byte, keyid, keyurl string) (Settings, error) {
	if len(key) == ed25519.PrivateKeySize {
		return Settings{Ed25519, ed25519.PrivateKey(key), [144]byte{0x00}, keyid, keyurl}, nil
	}
	if len(key) == 144 {
		var priv [144]byte
		copy(priv[:], key)
		return Settings{Ed448, nil, priv, keyid, keyurl}, nil
	}
	return Settings{}, errors.New("private key has wrong size")
}
