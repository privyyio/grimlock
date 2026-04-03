package grimlock

import (
	"github.com/privyyio/grimlock/go/grimlock/types"
	v1 "github.com/privyyio/grimlock/go/grimlock/v1"
)

// Grimlock is the main crypto module API
// Default export points to the latest version (v1)
type Grimlock struct {
	*v1.API
}

// Default is the default Grimlock instance (points to latest version)
var Default = &Grimlock{
	API: v1.V1,
}

// New creates a new Grimlock instance with the latest version
func New() *Grimlock {
	return Default
}

// NewWithVersion creates a Grimlock instance with a specific version
func NewWithVersion(version string) (*Grimlock, error) {
	switch version {
	case "v1":
		return &Grimlock{API: v1.V1}, nil
	// case "v2":
	//     return &Grimlock{API: v2.V2}, nil
	default:
		manager := GetVersionManager()
		_, err := manager.GetVersion(version)
		if err != nil {
			return nil, err
		}
		// For now, default to v1 if version exists but not implemented
		return &Grimlock{API: v1.V1}, nil
	}
}

// Convenience functions that delegate to the default instance

// GenerateKeyPair generates a new X25519 key pair
func GenerateKeyPair() (*types.KeyPairV1, error) {
	return Default.GenerateKeyPair()
}

// DerivePasscodeKey derives a key from a passcode using Argon2id
func DerivePasscodeKey(passcode string, params types.KdfParams) ([]byte, error) {
	return Default.DerivePasscodeKey(passcode, params)
}

// DeriveRecoveryKey derives a key from recovery key bytes using HKDF-SHA512
func DeriveRecoveryKey(recoveryKeyBytes []byte) ([]byte, error) {
	return Default.DeriveRecoveryKey(recoveryKeyBytes)
}

// EncryptPrivateKey encrypts a private key using AES-256-GCM
func EncryptPrivateKey(privateKey, encryptionKey, aad []byte) (*types.EncryptedPrivateKeyV1, error) {
	return Default.EncryptPrivateKey(privateKey, encryptionKey, aad)
}

// DecryptPrivateKey decrypts a private key using AES-256-GCM
func DecryptPrivateKey(encrypted *types.EncryptedPrivateKey, encryptionKey, aad []byte) ([]byte, error) {
	return Default.DecryptPrivateKey(encrypted, encryptionKey, aad)
}

// EncryptMessage encrypts a message payload using ephemeral key ECDH + AES-256-GCM
func EncryptMessage(payload types.MessagePayload, userPublicKey []byte, context types.MessageContext) (*types.EncryptedMessageV1, error) {
	return Default.EncryptMessage(payload, userPublicKey, context)
}

// DecryptMessage decrypts a message using user private key and ECDH
func DecryptMessage(encrypted *types.EncryptedMessage, userPrivateKey []byte, context types.MessageContext, metadata []byte) (*types.MessagePayload, error) {
	return Default.DecryptMessage(encrypted, userPrivateKey, context, metadata)
}

// GenerateRecoveryKey generates a new cryptographically secure recovery key
func GenerateRecoveryKey() (*types.RecoveryKey, error) {
	return Default.GenerateRecoveryKey()
}

// ComputeSharedSecret performs X25519 ECDH to compute a shared secret
func ComputeSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	return Default.ComputeSharedSecret(privateKey, publicKey)
}

// GenerateSalt generates a random salt for key derivation
func GenerateSalt() ([]byte, error) {
	return Default.GenerateSalt()
}

// GenerateDefaultKdfParams generates default KDF parameters with a new random salt
func GenerateDefaultKdfParams() (types.KdfParams, error) {
	return Default.GenerateDefaultKdfParams()
}
