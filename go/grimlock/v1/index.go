package v1

import (
	"github.com/privyy/grimlock/types"
	"github.com/privyy/grimlock/utils"
)

// API represents the v1 API interface
type API struct {
	Version   string
	Constants CryptoConstants
}

// V1 is the v1 API instance
var V1 = &API{
	Version:   "v1",
	Constants: Constants,
}

// Key Generation

// GenerateKeyPair generates a new X25519 key pair
func (api *API) GenerateKeyPair() (*types.KeyPairV1, error) {
	return GenerateKeyPair()
}

// ValidateKeyPair validates that a key pair is well-formed
func (api *API) ValidateKeyPair(keyPair *types.KeyPair) error {
	return ValidateKeyPair(keyPair)
}

// Key Derivation

// DerivePasscodeKey derives a key from a passcode using Argon2id
func (api *API) DerivePasscodeKey(passcode string, params types.KdfParams) ([]byte, error) {
	return DerivePasscodeKey(passcode, params)
}

// DeriveRecoveryKey derives a key from recovery key bytes using HKDF-SHA512
func (api *API) DeriveRecoveryKey(recoveryKeyBytes []byte) ([]byte, error) {
	return DeriveRecoveryKey(recoveryKeyBytes)
}

// GenerateSalt generates a random salt for key derivation
func (api *API) GenerateSalt() ([]byte, error) {
	return GenerateSalt()
}

// GenerateDefaultKdfParams generates default KDF parameters with a new random salt
func (api *API) GenerateDefaultKdfParams() (types.KdfParams, error) {
	return GenerateDefaultKdfParams()
}

// Private Key Operations

// EncryptPrivateKey encrypts a private key using AES-256-GCM
func (api *API) EncryptPrivateKey(privateKey, encryptionKey, aad []byte) (*types.EncryptedPrivateKeyV1, error) {
	return EncryptPrivateKey(privateKey, encryptionKey, aad)
}

// DecryptPrivateKey decrypts a private key using AES-256-GCM
func (api *API) DecryptPrivateKey(encrypted *types.EncryptedPrivateKey, encryptionKey, aad []byte) ([]byte, error) {
	return DecryptPrivateKey(encrypted, encryptionKey, aad)
}

// Message Operations

// EncryptMessage encrypts a message payload using ephemeral key ECDH + AES-256-GCM
func (api *API) EncryptMessage(payload types.MessagePayload, userPublicKey []byte, context types.MessageContext) (*types.EncryptedMessageV1, error) {
	return EncryptMessage(payload, userPublicKey, context)
}

// DecryptMessage decrypts a message using user private key and ECDH
func (api *API) DecryptMessage(encrypted *types.EncryptedMessage, userPrivateKey []byte, context types.MessageContext, metadata []byte) (*types.MessagePayload, error) {
	return DecryptMessage(encrypted, userPrivateKey, context, metadata)
}

// Recovery Key Operations

// GenerateRecoveryKey generates a new cryptographically secure recovery key
func (api *API) GenerateRecoveryKey() (*types.RecoveryKey, error) {
	return GenerateRecoveryKey()
}

// EncryptPrivateKeyWithRecoveryKey encrypts a private key using a recovery key
func (api *API) EncryptPrivateKeyWithRecoveryKey(privateKey, recoveryKey, aad []byte) (*types.EncryptedPrivateKeyV1, error) {
	return EncryptPrivateKeyWithRecoveryKey(privateKey, recoveryKey, aad)
}

// DecryptPrivateKeyWithRecoveryKey decrypts a private key using a recovery key
func (api *API) DecryptPrivateKeyWithRecoveryKey(encrypted *types.EncryptedPrivateKey, recoveryKey, aad []byte) ([]byte, error) {
	return DecryptPrivateKeyWithRecoveryKey(encrypted, recoveryKey, aad)
}

// ValidateRecoveryKey validates that a recovery key is well-formed
func (api *API) ValidateRecoveryKey(recoveryKey []byte) error {
	return ValidateRecoveryKey(recoveryKey)
}

// ECDH Operations

// ComputeSharedSecret performs X25519 ECDH to compute a shared secret
func (api *API) ComputeSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	return ComputeSharedSecret(privateKey, publicKey)
}

// Serialization Utilities

// SerializeKeyPair serializes a key pair to base64-encoded strings
func (api *API) SerializeKeyPair(keyPair *types.KeyPair) *types.SerializedKeyPair {
	return utils.SerializeKeyPair(keyPair)
}

// DeserializeKeyPair deserializes a base64-encoded key pair
func (api *API) DeserializeKeyPair(serialized *types.SerializedKeyPair) (*types.KeyPair, error) {
	return utils.DeserializeKeyPair(serialized)
}

// SerializeEncryptedPrivateKey serializes an encrypted private key to JSON
func (api *API) SerializeEncryptedPrivateKey(encrypted *types.EncryptedPrivateKey) ([]byte, error) {
	return utils.SerializeEncryptedPrivateKey(encrypted)
}

// DeserializeEncryptedPrivateKey deserializes an encrypted private key from JSON
func (api *API) DeserializeEncryptedPrivateKey(data []byte) (*types.EncryptedPrivateKey, error) {
	return utils.DeserializeEncryptedPrivateKey(data)
}

// SerializeEncryptedMessage serializes an encrypted message to JSON
func (api *API) SerializeEncryptedMessage(encrypted *types.EncryptedMessage) ([]byte, error) {
	return utils.SerializeEncryptedMessage(encrypted)
}

// DeserializeEncryptedMessage deserializes an encrypted message from JSON
func (api *API) DeserializeEncryptedMessage(data []byte) (*types.EncryptedMessage, error) {
	return utils.DeserializeEncryptedMessage(data)
}

// Memory Security

// SecureErase securely erases sensitive data from memory
func (api *API) SecureErase(data []byte) {
	SecureErase(data)
}

// SecureEraseMultiple erases multiple byte slices
func (api *API) SecureEraseMultiple(data ...[]byte) {
	SecureEraseMultiple(data...)
}
