Modular JWT / JWS provider in Golang
====================================

[![CircleCI](https://img.shields.io/circleci/project/github/FossoresLP/go-jwt/master.svg?style=flat-square)](https://circleci.com/gh/FossoresLP/go-jwt)
[![Coveralls](https://img.shields.io/coveralls/github/FossoresLP/go-jwt/master.svg?style=flat-square)](https://coveralls.io/github/FossoresLP/go-jwt)
[![Codacy](https://img.shields.io/codacy/grade/943c64e6d6ae481887224e6fe106a6a2.svg?style=flat-square)](https://www.codacy.com/app/FossoresLP/go-jwt)
[![Licensed under: Boost Software License](https://img.shields.io/badge/style-BSL--1.0-red.svg?longCache=true&style=flat-square&label=License)](https://github.com/FossoresLP/go-jwt/blob/master/LICENSE.md)
[![GoDoc](https://img.shields.io/badge/style-reference-blue.svg?longCache=true&style=flat-square&label=GoDoc)](https://godoc.org/github.com/FossoresLP/go-jwt)

This packages implements JSON Web Token as defined in [RFC 7519](https://tools.ietf.org/html/rfc7519) in Go.

This package is not capable of validating signatures on it's own. It is made to be modular and needs packages that provide their own signature algorithms.

Data structures
---------------

JWTs are stored as a struct with the following layout

```go
type JWT struct {
	Header struct {
		Typ string // Type of the token, has to be a JWT.
		Alg string // Algorithm used to sign the token (this package signs using EdDSA).
		Kid string // Key ID of the key used to sign the token.
		Jku string // URL presenting public key necessary for validation.
	}
	Content []byte // Should be either a map with strings as keys or a struct to adhere to the standard.
}
```

This package will decode the header of the token using a struct so some values could get lost.

It will try to validate the token using the registered signature algorithms. To get the validation result use `token.Valid()`.

Currently only NotBefore (`nbf`) and Expires (`exp`) are checked, but validation modules are in the works.

All further handling of the content is in the hands of the user, as the content is exposed as a JSON string (although it is a byte slice).

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
token.Valid() (error)
```

Keep in mind that this function currently only validates the hash and checks if the token is valid at the current point in time if `exp` and/or `nbf` are set.