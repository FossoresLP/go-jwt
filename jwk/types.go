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

type KeyType string

const (
	//Elliptic Curve
	KeyTypeEC KeyType = "EC"

	// RSA
	KeyTypeRSA KeyType = "RSA"

	// Octet sequence
	KeyTypeOct KeyType = "oct"

	// Octet string key pairs
	KeyTypeOKP KeyType = "OKP"

	// KeyTypeInternal signalizes this key has been created in drop-in replacement mode for publickey.PublicKey
	KeyTypeInternal KeyType = "internal"
)

type Use string

const (
	// Digital Signature or MAC
	UseSig Use = "sig"

	// Encryption
	UseEnc Use = "enc"
)

type KeyOperation string

const (
	// Compute digital signature or MAC
	KeyOperationSign KeyOperation = "sign"

	// Verify digital signature or MAC
	KeyOperationVerify KeyOperation = "verify"

	// Encrypt content
	KeyOperationEncrypt KeyOperation = "encrypt"

	// Decrypt content and validate decryption, if applicable
	KeyOperationDecrypt KeyOperation = "decrypt"

	// Encrypt key
	KeyOperationWrapKey KeyOperation = "wrapKey"

	// Decrypt key and validate decryption, if applicable
	KeyOperationUnwrapKey KeyOperation = "unwrapKey"

	// Derive key
	KeyOperationDeriveKey KeyOperation = "deriveKey"

	// Derive bits not to be used as a key
	KeyOperationDeriveBits KeyOperation = "deriveBits"
)

type Algorithm string

const (
	//HMAC using SHA-256
	HS256 Algorithm = "HS256"
	//HMAC using SHA-384
	HS384 Algorithm = "HS384"
	//HMAC using SHA-512
	HS512 Algorithm = "HS512"
	//RSASSA-PKCS1-v1_5 using SHA-256
	RS256 Algorithm = "RS256"
	//RSASSA-PKCS1-v1_5 using SHA-384
	RS384 Algorithm = "RS384"
	//RSASSA-PKCS1-v1_5 using SHA-512
	RS512 Algorithm = "RS512"
	//ECDSA using P-256 and SHA-256
	ES256 Algorithm = "ES256"
	//ECDSA using P-384 and SHA-384
	ES384 Algorithm = "ES384"
	//ECDSA using P-521 and SHA-512
	ES512 Algorithm = "ES512"
	//RSASSA-PSS using SHA-256 and MGF1 with SHA-256
	PS256 Algorithm = "PS256"
	//RSASSA-PSS using SHA-384 and MGF1 with SHA-384
	PS384 Algorithm = "PS384"
	//RSASSA-PSS using SHA-512 and MGF1 with SHA-512
	PS512 Algorithm = "PS512"
	//No digital signature or MAC performed
	None Algorithm = "none"
	//EdDSA signature algorithms
	EdDSA Algorithm = "EdDSA"
)
