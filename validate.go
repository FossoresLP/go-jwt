package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Valid returns an error when the hash does not match the content
func (jwt JWT) Valid() error {
	return jwt.validationError
}

func (jwt JWT) validate(data, signature []byte) error {
	alg, err := jwt.Header.getAlgorithm()
	if err != nil {
		return err
	}

	// Check the hash using the Verify function of the algorithm declared by the header
	if err := alg.Verify(data, signature, jwt.Header); err != nil {
		return err
	}

	return checkTimestamps(jwt.Content)
}

func (h Header) getAlgorithm() (Algorithm, error) {
	a, ok := algorithms[h.Alg]
	if !ok {
		return nil, fmt.Errorf("algorithm %s is not supported", h.Alg)
	}
	return a, nil
}

func checkTimestamps(c []byte) error {
	var timestamps struct {
		Expires   int64 `json:"exp"`
		NotBefore int64 `json:"nbf"`
	}

	if err := json.Unmarshal(c, &timestamps); err != nil {
		return nil // Ignore if content cannot be decoded for now
	}

	if timestamps.Expires != 0 && time.Unix(timestamps.Expires, 0).Before(time.Now().UTC()) {
		return errors.New("jwt has expired")
	}

	if timestamps.NotBefore != 0 && time.Unix(timestamps.NotBefore, 0).After(time.Now().UTC()) {
		return errors.New("jwt is not valid, yet")
	}

	return nil
}
