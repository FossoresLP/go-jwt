package jwt

// MarshalText provides encoding.TextMarshaler
func (jwt JWT) MarshalText() ([]byte, error) {
	return jwt.Encode()
}

// UnmarshalText provides encoding.TextUnmarshaler
func (jwt *JWT) UnmarshalText(in []byte) error {
	token, err := Decode(in)
	if err != nil {
		return err
	}
	*jwt = token
	return nil
}

// MarshalBinary provides encoding.BinaryMarshaler
func (jwt JWT) MarshalBinary() ([]byte, error) {
	return jwt.Encode()
}

// UnmarshalBinary provides encoding.BinaryUnmarshaler
func (jwt *JWT) UnmarshalBinary(in []byte) error {
	token, err := Decode(in)
	if err != nil {
		return err
	}
	*jwt = token
	return nil
}
