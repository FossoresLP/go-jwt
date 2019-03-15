package eddsa

import (
	"errors"

	"github.com/fossoreslp/go-uuid-v4"
	"github.com/otrv4/ed448"
	"golang.org/x/crypto/ed25519"
)

func generateEd25519KeySet() (Ed25519KeySet, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return Ed25519KeySet{}, err
	}
	id, err := uuid.NewString()
	if err != nil {
		return Ed25519KeySet{}, err
	}
	return Ed25519KeySet{priv, pub, id, "", true, true}, nil
}

func generateEd448KeySet() (Ed448KeySet, error) {
	curve := ed448.NewCurve()
	priv, pub, ok := curve.GenerateKeys()
	if !ok {
		return Ed448KeySet{}, errors.New("failed to generate Ed448 keys")
	}
	id, err := uuid.NewString()
	if err != nil {
		return Ed448KeySet{}, err
	}
	return Ed448KeySet{priv, pub, id, "", true, true}, nil
}
