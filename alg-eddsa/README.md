EdDSA Signature Provider
========================

**Test coverage:** Fully tested using unit tests and integration tests. No static tests of signing and verification.

**Important:**

- Ed448 is provided by a package that is marked as unstable by it's developers so use it with care.
- Due to the limited number of implementations of RFC 8037 out there, this package is only tested against itself.

This package implements a verification and siging provider using the EdDSA algorithms for JWT / JWS as specified in [RFC 8037](https://tools.ietf.org/html/rfc8037).

How to initialize
-----------------

```go
const (
	Ed25519 = 1
	Ed448 = 2
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

**Important:** Ed448 currently does not support the private key format defined in RFC 8032. It uses a 144 byte private key consisting of the private, public and symmetric key in that order.

The provider has to be registered using the name `EdDSA` to be compliant with RFC 8037. It will be able to verify signatures generated using both Ed25519 and Ed448 but can only sign using the algorithm selected on initialization.

Managing public keys
--------------------

```go
provider.CurrentKey() publickey.PublicKey

provider.AddPublicKey(key publickey.PublicKey) error
provider.RemovePublicKey(keyID string)
```

To retrieve the public key corresponding to the private key used for signing, use `provider.CurrentKey`.

Adding a public key is done via `provider.AddPublicKey` while removing works via `provider.RemovePublicKey`.
