package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

// New returns a new JWT containing content
// Content has to be encoded JSON
func New(content []byte) JWT {
	return JWT{Header{Typ: "JWT"}, content, nil}
}

// Encode a JWT to a byte slice
func (t JWT) Encode() ([]byte, error) {
	if defaultAlgorithm == "" {
		return nil, errors.New("default algorithm is not set - cannot sign JWT")
	}
	alg := signatureProviders[defaultAlgorithm]
	if alg == nil {
		return nil, errors.New("cannot access default algorithm")
	}
	alg.Header(&t.Header)
	header := encodeHeader(t.Header)
	content := b64encode(t.Content)
	sig, err := alg.Sign(join(header, content))
	if err != nil {
		return nil, err
	}
	hash := b64encode(sig)
	return join(header, content, hash), nil
}

func b64encode(data []byte) []byte {
	out := make([]byte, base64.RawURLEncoding.EncodedLen(len(data)))
	base64.RawURLEncoding.Encode(out, data)
	return out
}

func encodeHeader(h Header) []byte {
	json, _ := json.Marshal(h)
	return b64encode(json)
}

func join(b ...[]byte) []byte {
	if len(b) <= 0 {
		return nil
	}
	result := b[0]
	if len(b) == 1 {
		return result
	}
	for i := range b {
		if i > 0 {
			result = append(result, '.')
			result = append(result, b[i]...)
		}
	}
	return result
}
