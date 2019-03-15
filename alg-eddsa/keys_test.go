package eddsa

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"
)

func Test_generateEd25519KeySet(t *testing.T) {
	random := rand.Reader
	rand.Reader = bytes.NewReader(nil)
	keyset, err := generateEd25519KeySet()
	if err == nil {
		t.Error("Generating new Ed25519 keys did not fail with invalid random generator")
	}
	if !reflect.DeepEqual(keyset, Ed25519KeySet{}) {
		t.Errorf("Expected empty keyset on error but is %+v", keyset)
	}
	b := [32]byte{0x00}
	rand.Reader = bytes.NewReader(b[:])
	keyset, err = generateEd25519KeySet()
	if err == nil {
		t.Error("Generating new UUID for key did not fail with empty random generator")
	}
	if !reflect.DeepEqual(keyset, Ed25519KeySet{}) {
		t.Errorf("Expected empty keyset on error but is %+v", keyset)
	}
	rand.Reader = random
}

func Test_generateEd448KeySet(t *testing.T) {
	random := rand.Reader
	rand.Reader = bytes.NewReader(nil)
	keyset, err := generateEd448KeySet()
	if err == nil {
		t.Error("Generating new Ed448 keys did not fail with invalid random generator")
	}
	if !reflect.DeepEqual(keyset, Ed448KeySet{}) {
		t.Errorf("Expected empty keyset on error but is %+v", keyset)
	}
	b := [32]byte{0x00}
	rand.Reader = bytes.NewReader(b[:])
	keyset, err = generateEd448KeySet()
	if err == nil {
		t.Error("Generating new UUID for key did not fail with empty random generator")
	}
	if !reflect.DeepEqual(keyset, Ed448KeySet{}) {
		t.Errorf("Expected empty keyset on error but is %+v", keyset)
	}
	rand.Reader = random
}
