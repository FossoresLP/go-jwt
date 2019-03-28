package jwt

// Header contains the header data of a JSON web token
type Header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Jku string `json:"jku,omitempty"`
	Crv string `json:"crv,omitempty"`
}

// JWT contains the decoded header and encoded content of a JSON web token
type JWT struct {
	Header          Header
	Content         []byte
	validationError error
}

// SignatureProvider is an interface for algorithms used to sign and validate a JWS
type SignatureProvider interface {
	Sign([]byte) ([]byte, error)
	Verify([]byte, []byte, Header) error
	Header(*Header)
}

// ContentValidationProvider is an interface for verification providers used to validate the content of a JWT
type ContentValidationProvider interface {
	Validate([]byte) error
}
