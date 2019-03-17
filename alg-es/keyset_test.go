package es

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"reflect"
	"testing"

	"github.com/fossoreslp/go-jwt/publickey"
)

var (
	x, _ = new(big.Int).SetString("53362156244743717582302245396579768295291970453913383836603205696230085410059", 10)
	y, _ = new(big.Int).SetString("30291755020966801726600908749968268600863491590438969900821061765762053214603", 10)
	d, _ = new(big.Int).SetString("81441865675641311106028598596990373907775388393469674002729224480451685045463", 10)
)

func TestKeySet_SetKeys_PrivateKey(t *testing.T) {
	ks := KeySet{}
	// Test SetKeys with nil keys
	err := ks.SetKeys(nil, nil)
	if err != nil {
		t.Errorf("SetKeys() with nil keys should not return an error but returned: %s", err.Error())
	}

	// Define keys for testing including encoded versions
	priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	ec := []byte{0x30, 0x77, 0x2, 0x1, 0x1, 0x4, 0x20, 0xb4, 0xe, 0x76, 0x62, 0xe0, 0x1f, 0x27, 0x4d, 0x77, 0x7d, 0x23, 0xcd, 0x82, 0xe9, 0xd2, 0x1d, 0x3b, 0xf8, 0x40, 0xf7, 0xf4, 0x9f, 0x22, 0xf8, 0xb6, 0x36, 0xca, 0xd6, 0xa0, 0xb8, 0xd4, 0xd7, 0xa0, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0xa1, 0x44, 0x3, 0x42, 0x0, 0x4, 0x75, 0xf9, 0xe8, 0xfd, 0x91, 0xc8, 0x84, 0x61, 0x5, 0xaa, 0xd4, 0x1d, 0x6a, 0x36, 0xb3, 0xce, 0xdc, 0xa2, 0x62, 0x82, 0x35, 0xc2, 0xf9, 0xb8, 0x1, 0x1a, 0xdb, 0xca, 0x77, 0xec, 0xbd, 0xb, 0x42, 0xf8, 0x86, 0x98, 0x63, 0x8c, 0xbf, 0x9b, 0xca, 0xab, 0xa3, 0x39, 0x9c, 0xc1, 0x2, 0x35, 0xb8, 0x5a, 0x49, 0x25, 0x52, 0xb0, 0xa0, 0x4, 0xe2, 0xe7, 0xf2, 0x15, 0x79, 0xaa, 0x91, 0x8b}
	pkcs8 := []byte{0x30, 0x81, 0x87, 0x2, 0x1, 0x0, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x4, 0x6d, 0x30, 0x6b, 0x2, 0x1, 0x1, 0x4, 0x20, 0xb4, 0xe, 0x76, 0x62, 0xe0, 0x1f, 0x27, 0x4d, 0x77, 0x7d, 0x23, 0xcd, 0x82, 0xe9, 0xd2, 0x1d, 0x3b, 0xf8, 0x40, 0xf7, 0xf4, 0x9f, 0x22, 0xf8, 0xb6, 0x36, 0xca, 0xd6, 0xa0, 0xb8, 0xd4, 0xd7, 0xa1, 0x44, 0x3, 0x42, 0x0, 0x4, 0x75, 0xf9, 0xe8, 0xfd, 0x91, 0xc8, 0x84, 0x61, 0x5, 0xaa, 0xd4, 0x1d, 0x6a, 0x36, 0xb3, 0xce, 0xdc, 0xa2, 0x62, 0x82, 0x35, 0xc2, 0xf9, 0xb8, 0x1, 0x1a, 0xdb, 0xca, 0x77, 0xec, 0xbd, 0xb, 0x42, 0xf8, 0x86, 0x98, 0x63, 0x8c, 0xbf, 0x9b, 0xca, 0xab, 0xa3, 0x39, 0x9c, 0xc1, 0x2, 0x35, 0xb8, 0x5a, 0x49, 0x25, 0x52, 0xb0, 0xa0, 0x4, 0xe2, 0xe7, 0xf2, 0x15, 0x79, 0xaa, 0x91, 0x8b}

	// Test SetKeys with EC-encoded private key
	err = ks.SetKeys(ec, nil)
	if err != nil {
		t.Errorf("SetKeys() with EC private key should not return an error but returned: %s", err.Error())
	}
	if !reflect.DeepEqual(ks.private, priv) {
		t.Errorf("SetKeys() with EC private key should be decoded to %+v but is %+v", priv, ks.private)
	}

	// Test SetKeys with PKCS8-encoded private key
	err = ks.SetKeys(pkcs8, nil)
	if err != nil {
		t.Errorf("SetKeys() with PKCS8 private key should not return an error but returned: %s", err.Error())
	}
	if !reflect.DeepEqual(ks.private, priv) {
		t.Errorf("SetKeys() with PKCS8 private key should be decoded to %+v but is %+v", priv, ks.private)
	}

	// Test SetKeys with invalid private key
	err = ks.SetKeys([]byte("not a key"), nil)
	if err == nil {
		t.Error("SetKeys() with invalid private key should return an error but did not")
	}

	// Test SetKeys with PKCS8-encoded private key of an invalid type (RSA 512)
	err = ks.SetKeys([]byte{0x30, 0x42, 0x2, 0x1, 0x0, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1, 0x5, 0x0, 0x4, 0x2e, 0x30, 0x2c, 0x2, 0x1, 0x0, 0x2, 0x5, 0x0, 0xd6, 0xc8, 0xbc, 0x87, 0x2, 0x3, 0x1, 0x0, 0x1, 0x2, 0x4, 0x28, 0x39, 0x64, 0x21, 0x2, 0x3, 0x0, 0xfa, 0x3f, 0x2, 0x3, 0x0, 0xdb, 0xb9, 0x2, 0x2, 0x50, 0xed, 0x2, 0x3, 0x0, 0xa6, 0x49, 0x2, 0x2, 0x1d, 0xb0}, nil)
	if err == nil {
		t.Error("SetKeys() with unsupported private key type (RSA / DSA) should fail but did not")
	}
}

func TestKeySet_SetKeys_PublicKey(t *testing.T) {
	ks := KeySet{}
	// Define key for testing including encoded version
	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	pkix := []byte{0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x75, 0xf9, 0xe8, 0xfd, 0x91, 0xc8, 0x84, 0x61, 0x5, 0xaa, 0xd4, 0x1d, 0x6a, 0x36, 0xb3, 0xce, 0xdc, 0xa2, 0x62, 0x82, 0x35, 0xc2, 0xf9, 0xb8, 0x1, 0x1a, 0xdb, 0xca, 0x77, 0xec, 0xbd, 0xb, 0x42, 0xf8, 0x86, 0x98, 0x63, 0x8c, 0xbf, 0x9b, 0xca, 0xab, 0xa3, 0x39, 0x9c, 0xc1, 0x2, 0x35, 0xb8, 0x5a, 0x49, 0x25, 0x52, 0xb0, 0xa0, 0x4, 0xe2, 0xe7, 0xf2, 0x15, 0x79, 0xaa, 0x91, 0x8b}

	// Test SetKeys with a RSA public key
	err := ks.SetKeys(nil, pkix)
	if err != nil {
		t.Errorf("SetKeys() with PKIX public key should not return an error but returned: %s", err.Error())
	}
	if !reflect.DeepEqual(ks.public, &pub) {
		t.Errorf("SetKeys() with PKIX public key should be decoded to %+v but is %+v", &pub, ks.public)
	}

	// Test SetKeys with invalid public key
	err = ks.SetKeys(nil, []byte("not a key"))
	if err == nil {
		t.Error("SetKeys() with invalid public key should return an error but did not")
	}

	// Test SetKeys with invalid public key type (RSA)
	err = ks.SetKeys(nil, []byte{0x30, 0x20, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1, 0x5, 0x0, 0x3, 0xf, 0x0, 0x30, 0xc, 0x2, 0x5, 0x0, 0xd6, 0xc8, 0xbc, 0x87, 0x2, 0x3, 0x1, 0x0, 0x1})
	if err == nil {
		t.Error("SetKeys() with unsupported public key type (RSA / DSA) should fail but did not")
	}
}

func TestKeySet_SetKeyID(t *testing.T) {
	ks := KeySet{}
	ks.SetKeyID("key_id")
	if !reflect.DeepEqual(ks, KeySet{kid: "key_id"}) {
		t.Errorf("SetKeyID failed to set key ID. Expected %+v but got %+v", KeySet{kid: "key_id"}, ks)
	}
}

func TestKeySet_SetKeyURL(t *testing.T) {
	ks := KeySet{}
	ks.SetKeyURL("key_url")
	if !reflect.DeepEqual(ks, KeySet{jku: "key_url"}) {
		t.Errorf("SetKeyURL failed to set key URL. Expected %+v but got %+v", KeySet{jku: "key_url"}, ks)
	}
}

func TestKeySet_GetPublicKey(t *testing.T) {
	k := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	tests := []struct {
		name string
		ks   KeySet
		want publickey.PublicKey
	}{
		{"Normal", KeySet{public: &k, kid: "key_id"}, publickey.New([]byte{0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x75, 0xf9, 0xe8, 0xfd, 0x91, 0xc8, 0x84, 0x61, 0x5, 0xaa, 0xd4, 0x1d, 0x6a, 0x36, 0xb3, 0xce, 0xdc, 0xa2, 0x62, 0x82, 0x35, 0xc2, 0xf9, 0xb8, 0x1, 0x1a, 0xdb, 0xca, 0x77, 0xec, 0xbd, 0xb, 0x42, 0xf8, 0x86, 0x98, 0x63, 0x8c, 0xbf, 0x9b, 0xca, 0xab, 0xa3, 0x39, 0x9c, 0xc1, 0x2, 0x35, 0xb8, 0x5a, 0x49, 0x25, 0x52, 0xb0, 0xa0, 0x4, 0xe2, 0xe7, 0xf2, 0x15, 0x79, 0xaa, 0x91, 0x8b}, "key_id")},
		{"Unknown curve", KeySet{public: &ecdsa.PublicKey{Curve: new(elliptic.CurveParams), X: big.NewInt(1), Y: big.NewInt(2)}}, publickey.PublicKey{}},
		{"No key", KeySet{}, publickey.PublicKey{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ks.GetPublicKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeySet.GetPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
