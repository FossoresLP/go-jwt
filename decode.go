package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// Decode decodes a JWT and check it's validity (use Validate() on JWT to see if it is valid)
func Decode(in []byte) (data JWT, err error) {
	// Split the JWT into it's sections (header, content, hash)
	sections := bytes.Split(in, []byte("."))
	if len(sections) != 3 {
		err = errors.New("invalid number of sections")
		return
	}

	// Decode Header
	// Base64
	headerJSON := make([]byte, base64.RawURLEncoding.DecodedLen(len(sections[0])))
	if _, err = base64.RawURLEncoding.Decode(headerJSON, sections[0]); err != nil {
		return
	}

	// JSON
	if err = json.Unmarshal(headerJSON, &data.Header); err != nil {
		return
	}
	if data.Header.Typ != "JWT" {
		err = errors.New("header suggests token is not a JWT")
		return
	}

	// Decode Content
	data.Content = make([]byte, base64.RawURLEncoding.DecodedLen(len(sections[1])))
	if _, err = base64.RawURLEncoding.Decode(data.Content, sections[1]); err != nil {
		return
	}

	// Decode Hash
	signature := make([]byte, base64.RawURLEncoding.DecodedLen(len(sections[2])))
	if n, e := base64.RawURLEncoding.Decode(signature, sections[2]); e != nil || n < 1 {
		err = errors.New("hash invalid")
		return
	}

	data.validationError = data.validate(join(sections[0], sections[1]), signature)

	return
}
