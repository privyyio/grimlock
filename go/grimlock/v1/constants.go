package v1

import "github.com/privyy-io/grimlock/go/grimlock/types"

// CryptoConstants contains all cryptographic constants for v1
type CryptoConstants struct {
	// Version identifier
	Version string

	// Key sizes (bytes)
	X25519PrivateKeySize int
	X25519PublicKeySize  int
	AESKeySize           int
	RecoveryKeySize      int

	// AES-GCM parameters
	GCMNonceSize int
	GCMTagSize   int

	// Argon2id default parameters
	DefaultArgon2Params types.Argon2Params

	// HKDF salt strings (with grimlock prefix)
	HKDFSaltEncryption string
	HKDFSaltRecovery   string

	// HKDF info strings (with grimlock prefix)
	HKDFInfoMessageKey          string
	HKDFInfoRecoveryDerivation  string
	HKDFInfoDualEncryption      string

	// Server pepper for passcode HMAC
	DefaultPepper string

	// Salt sizes
	KDFSaltSize      int
	HKDFSaltSize     int
}

// Constants is the v1 constants instance
var Constants = CryptoConstants{
	Version: "v1",

	// Key sizes (bytes)
	X25519PrivateKeySize: 32,
	X25519PublicKeySize:  32,
	AESKeySize:           32, // AES-256
	RecoveryKeySize:      32, // 256 bits

	// AES-GCM parameters
	GCMNonceSize: 12, // 96 bits (standard for GCM)
	GCMTagSize:   16, // 128 bits (standard for GCM)

	// Argon2id default parameters
	DefaultArgon2Params: types.Argon2Params{
		TimeCost:    4,              // 4 iterations
		MemoryCost:  128 * 1024,     // 128 MiB
		Parallelism: 2,              // 2 threads
	},

	// HKDF salt strings (with grimlock prefix)
	HKDFSaltEncryption: "grimlock-encryption-salt",
	HKDFSaltRecovery:   "grimlock-recovery-salt",

	// HKDF info strings (with grimlock prefix)
	HKDFInfoMessageKey:         "grimlock-message-key",
	HKDFInfoRecoveryDerivation: "grimlock-recovery-key-derivation",
	HKDFInfoDualEncryption:     "grimlock-dual-encryption",

	// Server pepper for passcode HMAC
	DefaultPepper: "grimlock-default-pepper",

	// Salt sizes
	KDFSaltSize:  32, // 256 bits for Argon2id
	HKDFSaltSize: 32, // 256 bits for HKDF
}
