Modular JWT / JWS provider in Golang
====================================

[![CircleCI](https://img.shields.io/circleci/project/github/FossoresLP/go-jwt/master.svg?style=flat-square)](https://circleci.com/gh/FossoresLP/go-jwt)
[![Codecov](https://img.shields.io/codecov/c/gh/FossoresLP/go-jwt.svg?style=flat-square)](https://codecov.io/gh/FossoresLP/go-jwt)
[![Codacy](https://img.shields.io/codacy/grade/52a3263fab6a4a3f8b22b2ae3bb93d32.svg?style=flat-square)](https://www.codacy.com/app/FossoresLP/go-jwt)
[![Licensed under: Boost Software License](https://img.shields.io/badge/style-BSL--1.0-red.svg?longCache=true&style=flat-square&label=License)](https://github.com/FossoresLP/go-jwt/blob/master/LICENSE.md)
[![GoDoc](https://img.shields.io/badge/style-reference-blue.svg?longCache=true&style=flat-square&label=GoDoc)](https://godoc.org/github.com/FossoresLP/go-jwt)

This packages implements JSON Web Token as defined in [RFC 7519](https://tools.ietf.org/html/rfc7519) in Go.

This package is not capable of validating signatures on it's own. It has a modular architecture and needs modules providing signature algorithms.

The default algorithms specified in [RFC7518](https://tools.ietf.org/html/rfc7518) and [RFC8037](https://tools.ietf.org/html/rfc8037) can be found in sub-packages in this repository.

EdDSA with Ed25519 and Ed448 (unstable), HMAC-SHA2, RSA PKCS#1 v1.5, RSA-PSS and ECDSA can all be found in the respective folders.

Data structures
---------------

JWTs are stored as a struct with the following layout

```go
type JWT struct {
	Header struct {
		Typ string // Type of the token, has to be JWT.
		Alg string // Algorithm used to sign the token (this package signs using EdDSA).
		Kid string // Key ID of the key used to sign the token.
		Jku string // URL presenting public key necessary for validation.
	}
	Content []byte // Encoded JSON as specified in RFC 7519 (Should be based on map or struct in Go)
}
```

This package will decode the header of the token using a struct so some values could get lost.

It will try to validate the token using the registered signature algorithms. To check if the token is valid use `token.Valid()` which returns a boolean. If you want to know the exact error, use `token.ValidationError()`.

The claims of a token can be validated manually or using validation providers. Some of those are included in validationFunctions.go but you can always create your own.

All further handling of the content is in the hands of the user, as the content is exposed as JSON (in form of a byte slice).

Usage
-----

### Generating a new JWT

Creating a JWT is quite easy. You just have to supply your content and this package will generate a JWT for you. New will return an error when an unsupported content type is used. Supported content types are structs and maps with strings as keys.

```go
jwt.New(content []byte) (JWT, error)
```

### Encoding a JWT

To actually use a JWT you will have to encode it. This is done by simply calling `Encode` on the JWT you created.

```go
token.Encode() (string, error)
```

### Decoding a JWT

To validate a JWT you will first have to decode it. Just supply it to the `Decode` function.

```go
jwt.Decode(encodedtoken) (JWT, error)
```

### Validating the hash

When decoding a JWT, it is automatically validated but you will have to retieve the result using:

```go
token.Valid() bool
token.ValidationError() error
```

Keep in mind that this only checks if the token was valid when it was decoded and also only using the validation providers registered at that time.