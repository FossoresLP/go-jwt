HMAC-SHA2 Signature Provider
============================

**Test coverage:** Fully tested using unit tests and integration tests. No static tests of signing and verification. Signing and verification manually validated against [jwt.io](https://jwt.io).

This package implements a verification and siging provider using the HMAC-SHA2 algorithms for JWT / JWS as specified in [RFC 7518](https://tools.ietf.org/html/rfc7518).

How to initialize
-----------------

```go
const (
	HS256 = 1
	HS384 = 2
	HS512 = 3
)

NewProvider(algorithm int) (Provider, error)
NewProviderWithKeyURL(algorithm int, keyURL string) (Provider, error)

NewSettings(key []byte, keyID string) (Settings, error)
NewSettingsWithKeyURL(key []byte, keyID, keyURL string) (Settings, error)
LoadProvider(settings Settings, algorithm int) (Provider, error)
```

There are two ways to initialize this package:

- Generate a new key using `NewProvider` which optionally may also include a key URL. Note that you will need to upload the public key to the key store manually.

- Load an existing key by creating a new `Settings` struct using `NewSettings` supplying the key as a byte slice (not encoded) and then calling `LoadProvider` with the settings.

The provider has to be registered using the name `HSxxx` to be compliant with RFC 7518. It will be able to sign and verify keys for the specified byte size only.

Managing public keys
--------------------

```go
provider.CurrentKey() publickey.PublicKey

provider.AddPublicKey(key publickey.PublicKey) error
provider.RemovePublicKey(keyID string)
```

To retrieve the signing / verification key, use `provider.CurrentKey`.

**Important:** Do not publish this key as it is used for both signing and verification.

Adding a public key is done via `provider.AddPublicKey` while removing works via `provider.RemovePublicKey`.
