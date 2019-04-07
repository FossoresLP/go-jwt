package jwk

// Curve is used to represent all curves supported in JWKs by this package.
type Curve string

const (
	// CurveEd25519 is a twisted Edwards curve with approx. 128 bits of security.
	CurveEd25519 Curve = "Ed25519"

	// CurveEd448 is an Edwards curve with approx. 224 bits of security.
	CurveEd448 Curve = "Ed448"

	// CurveP256 is the NIST curve P-256
	CurveP256 Curve = "P-256"

	// CurveP384 is the NIST curve P-384
	CurveP384 Curve = "P-384"

	// CurveP521 is the NIST curve P-521
	CurveP521 Curve = "P-521"

	// CurveX25519 indicates X25519 function key pairs
	CurveX25519 Curve = "X25519"

	// CurveX448 indicates X448 function key pairs
	CurveX448 Curve = "X448"
)

// KeyType indicates which type of key the JWK contains
type KeyType string

const (
	// KeyTypeEC is the key type for Elliptic Curve keys
	KeyTypeEC KeyType = "EC"

	// KeyTypeRSA is the key type for RSA keys
	KeyTypeRSA KeyType = "RSA"

	// KeyTypeOct is the key type for Octet sequence (symmetric / other) keys
	KeyTypeOct KeyType = "oct"

	// KeyTypeOKP is the key type for Octet string (EdDSA / other) keys
	KeyTypeOKP KeyType = "OKP"
)

// Use indicates how the contained key should be used
type Use string

const (
	// UseSig signalizes the key is meant for Digital Signature or MAC use
	UseSig Use = "sig"

	// UseEnc signalizes the key is meant for Encryption use
	UseEnc Use = "enc"
)

// KeyOperation indicates the intended key operations
type KeyOperation string

const (
	// KeyOperationSign indicates operation Compute digital signature or MAC
	KeyOperationSign KeyOperation = "sign"

	// KeyOperationVerify indicates operation Verify digital signature or MAC
	KeyOperationVerify KeyOperation = "verify"

	// KeyOperationEncrypt indicates operation Encrypt content
	KeyOperationEncrypt KeyOperation = "encrypt"

	// KeyOperationDecrypt indicates operation Decrypt content and validate decryption, if applicable
	KeyOperationDecrypt KeyOperation = "decrypt"

	// KeyOperationWrapKey indicates operation Encrypt key
	KeyOperationWrapKey KeyOperation = "wrapKey"

	// KeyOperationUnwrapKey indicates operation Decrypt key and validate decryption, if applicable
	KeyOperationUnwrapKey KeyOperation = "unwrapKey"

	// KeyOperationDeriveKey indicates operation Derive key
	KeyOperationDeriveKey KeyOperation = "deriveKey"

	// KeyOperationDeriveBits indicates operation Derive bits not to be used as a key
	KeyOperationDeriveBits KeyOperation = "deriveBits"
)

// Algorithm indicates the algorithm the key should be used with
type Algorithm string

const (
	// HS256 is HMAC using SHA-256
	HS256 Algorithm = "HS256"
	// HS384 is HMAC using SHA-384
	HS384 Algorithm = "HS384"
	// HS512 is HMAC using SHA-512
	HS512 Algorithm = "HS512"
	// RS256 is RSASSA-PKCS1-v1_5 using SHA-256
	RS256 Algorithm = "RS256"
	// RS384 is RSASSA-PKCS1-v1_5 using SHA-384
	RS384 Algorithm = "RS384"
	// RS512 is RSASSA-PKCS1-v1_5 using SHA-512
	RS512 Algorithm = "RS512"
	// ES256 is ECDSA using P-256 and SHA-256
	ES256 Algorithm = "ES256"
	// ES384 is ECDSA using P-384 and SHA-384
	ES384 Algorithm = "ES384"
	// ES512 is ECDSA using P-521 and SHA-512
	ES512 Algorithm = "ES512"
	// PS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256
	PS256 Algorithm = "PS256"
	// PS384 is RSASSA-PSS using SHA-384 and MGF1 with SHA-384
	PS384 Algorithm = "PS384"
	// PS512 is RSASSA-PSS using SHA-512 and MGF1 with SHA-512
	PS512 Algorithm = "PS512"
	// None is No digital signature or MAC performed
	None Algorithm = "none"
	// EdDSA is EdDSA signature algorithms
	EdDSA Algorithm = "EdDSA"
)
