API definitions for modules
===========================

This document defines which functions have to be implemented by modules to be usable with this package.

Signature providers
-------------------

### `NewProvider`

```go
NewProvider(parameters string) (Provider, []publickey.PublicKey, error)
```

`NewProvider` has to create a new Provider optionally taking in parameters as a string.
It has to generate new keys and return the public keys (in case there are any - see HMAC-SHA2).
A key ID should also be generated for every new key and should be included with the public keys.

### `NewProviderWithKeyURL`

```go
NewProviderWithKeyURL(parameters string, keyURL string) (Provider, []publickey.PublicKey, error)
```

`NewProviderWithKeyURL` has to work the same as `NewProvider` but must also add the key URL so that is is available to the `Header` function of the provider.

### `LoadProvider`

```go
LoadProvider(set KeySet..., parameters string) (Provider, error)
```

`LoadProvider` may be provided to enable users to load keys.
The function may take as many `KeySet`s as necessary for the algorithm the provider implements.
Optional parameters should be taken from a string.
Please note that each needed `KeySet` must be it's own parameter instead of some taking kind of array (no rest of parameters either).

### `Provider`

```go
type Provider interface {
	Sign([]byte) ([]byte, error)
	Verify([]byte, []byte, Header) error
	Header(*Header)
}
```

A `Provider` has to implement the following functionality:

`Sign(data []byte) (signature []byte, err error)` has to return the (not base64-encoded) signature the algorithm generates for the data provided as the input and an error to indicate whether signing was successful.

`Verify(data, signature []byte, h Header) (err error)` has to return an error indicating whether the signature could be validated. The header can be accessed for additional data.

`Header(h *Header)` has to set the necessary header parameters to indicate the used algorithm. It must also set the key ID and key URL in case the key designated for signing has any.

In case additional fields in the header are necessary, please open an issue on GitHub to discuss possible solutions.

### `KeySet`

```go
type KeySet interface {
	SetKeys([]byte, []byte) error
	SetKeyID(string)
	SetKeyURL(string)
	GetPublicKey() publickey.PublicKey
}
```

A `KeySet` is only necessary when supporting `LoadProvider` and has to implement the following functionality:

`SetKeys(privateKey, publicKey []byte) (err error)` has to set the keys of the `KeySet` by parsing the supplied byte slices and return an error indicating whether parsing was successful.

`SetKeyID(keyID string)` has to set the key ID of the `KeySet`

`SetKeyURL(keyURL string)` has to set the key URL of the `KeySet`

`GetPublicKey() publicKey publickey.PublicKey` has to return the public key (as a byte slice) and key ID of the `KeySet` as a `publickey.PublicKey`

Validation providers
--------------------

```go
func Validate(content []byte) error
```

A validation provider consists of a single function taking a byte slice containing the JSON-encoded body of the token and returns an error indication whether the token is valid. It has to unmarshal the JSON and perform all necessary checks to determine the validity of the claims.