Modular JWT / JWS provider in Golang
====================================

[![CircleCI](https://img.shields.io/circleci/project/github/FossoresLP/go-jwt/master.svg?style=flat-square)](https://circleci.com/gh/FossoresLP/go-jwt)
[![Codecov](https://img.shields.io/codecov/c/gh/FossoresLP/go-jwt.svg?style=flat-square)](https://codecov.io/gh/FossoresLP/go-jwt)
[![Codacy](https://img.shields.io/codacy/grade/52a3263fab6a4a3f8b22b2ae3bb93d32.svg?style=flat-square)](https://www.codacy.com/app/FossoresLP/go-jwt)
[![Licensed under: Boost Software License](https://img.shields.io/badge/style-BSL--1.0-red.svg?longCache=true&style=flat-square&label=License)](https://github.com/FossoresLP/go-jwt/blob/master/LICENSE.md)
[![GoDoc](https://img.shields.io/badge/style-reference-blue.svg?longCache=true&style=flat-square&label=GoDoc)](https://godoc.org/github.com/FossoresLP/go-jwt)

This packages implements JSON Web Token as defined in [RFC 7519](https://tools.ietf.org/html/rfc7519) in Go.

It is build with a modular architecture to make it easy to adapt to most use cases.

For this reason all verification of signatures and contents is implemented independently and does explicitly have to be activated.

All tokens decoded by this package will automatically be validated using the activated signature and content verification providers. To check if the token is valid use `token.Valid()` which returns a boolean. If you want to know the exact error, use `token.ValidationError()`.

The default algorithms for signature verification specified in [RFC7518](https://tools.ietf.org/html/rfc7518) and [RFC8037](https://tools.ietf.org/html/rfc8037) can be found in sub-packages in this repository.

EdDSA with Ed25519 and Ed448 (unstable), HMAC-SHA2, RSA PKCS#1 v1.5, RSA-PSS and ECDSA can all be found in the respective folders.

You may add a signature algorithm by calling `RegisterAlgorithm(name string, alg Algorithm) error` with name being the value of the `alg` header this algorithm uses and alg being a properly initialized instance of the respective algorithm. To enable signing and select the algorithm to use, call `SetSigningAlgorithm(name string) error` with the name of the algorithm to use.

The main package includes some implementations of content validation in `validationFunctions.go`. To add a content validator, call `AddValidationProvider(name string, provider VerificationProvider) error` with a name of your choosing and the initialized provider. It will automatically be used to validate all tokens that are decoded after adding it.

In case the providers included in this package do not fit your needs, you can always implement your own. For details see `API.md`.

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

Due to the header being a struct some values may be ignored when decoding.

Usage
-----

### Generating a new JWT

Creating a JWT is quite easy. You just have to supply your content encoded as JSON and this package will generate a JWT for you.

```go
jwt.New(content []byte) (JWT, error)
```

### Encoding a JWT

To actually use a JWT you will have to encode it. This is done by simply calling `Encode` on the JWT you created.

Please note that you will need to add a signature provider first and also set the singing provider to use.

```go
token.Encode() ([]byte, error)
```

### Decoding a JWT

To validate a JWT you will first have to decode it. Just supply it to the `Decode` function.

```go
jwt.Decode(encodedtoken []byte) (JWT, error)
```

### Validating the hash

When decoding a JWT, it is automatically validated but you will have to retieve the result using:

```go
token.Valid() bool
token.ValidationError() error
```

Keep in mind that this only checks if the token was valid when it was decoded and also only using the validation providers registered at that time.
You will also need to add the signature validation provider and add the necessary keys before decoding the token or it will be treated as invalid.
