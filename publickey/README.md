Public key implementation
=========================

This implementation of public keys differs from the interface `crypto` provides in that it only handles public keys as a byte slice and also stores a key ID with the key. It is therefore specifically made for JWS / JWK use. Note that it does not implement the JWK standard though.

Working with public keys
------------------------

```go
New(key []byte, keyID string) PublicKey

key.GetPublicKey() []byte
key.GetKeyID() string
```

A new public key can be initialized using `New` with the key as a byte slice and the key ID as a string.

To retrieve the public key slice from a public key, use `key.GetPublicKey`.
The key ID can similarly be retrieved using `key.GetKeyID`.