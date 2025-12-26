package v1

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/privyy/grimlock/types"
)

// GenerateRecoveryKey generates a new cryptographically secure recovery key
func GenerateRecoveryKey() (*types.RecoveryKey, error) {
	// Generate random 256-bit key
	key := make([]byte, Constants.RecoveryKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate recovery key: %w", err)
	}

	return &types.RecoveryKey{
		Key: key,
		// Note: Mnemonic generation (BIP39) is optional and can be added later
		// For now, we leave it empty. Client-side implementation may handle mnemonics.
	}, nil
}

// EncryptPrivateKeyWithRecoveryKey encrypts a private key using a recovery key
func EncryptPrivateKeyWithRecoveryKey(privateKey, recoveryKey []byte, aad []byte) (*types.EncryptedPrivateKeyV1, error) {
	if len(recoveryKey) != Constants.RecoveryKeySize {
		return nil, fmt.Errorf("invalid recovery key size: expected %d, got %d",
			Constants.RecoveryKeySize, len(recoveryKey))
	}

	// Derive encryption key from recovery key
	encryptionKey, err := DeriveRecoveryKey(recoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key from recovery key: %w", err)
	}
	defer SecureErase(encryptionKey)

	// Encrypt private key
	return EncryptPrivateKey(privateKey, encryptionKey, aad)
}

// DecryptPrivateKeyWithRecoveryKey decrypts a private key using a recovery key
func DecryptPrivateKeyWithRecoveryKey(encrypted *types.EncryptedPrivateKey, recoveryKey []byte, aad []byte) ([]byte, error) {
	if len(recoveryKey) != Constants.RecoveryKeySize {
		return nil, fmt.Errorf("invalid recovery key size: expected %d, got %d",
			Constants.RecoveryKeySize, len(recoveryKey))
	}

	// Derive encryption key from recovery key
	encryptionKey, err := DeriveRecoveryKey(recoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key from recovery key: %w", err)
	}
	defer SecureErase(encryptionKey)

	// Decrypt private key
	return DecryptPrivateKey(encrypted, encryptionKey, aad)
}

// ValidateRecoveryKey validates that a recovery key is well-formed
func ValidateRecoveryKey(recoveryKey []byte) error {
	if len(recoveryKey) != Constants.RecoveryKeySize {
		return fmt.Errorf("invalid recovery key size: expected %d, got %d",
			Constants.RecoveryKeySize, len(recoveryKey))
	}

	// Check that recovery key is not all zeros
	allZero := true
	for _, b := range recoveryKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("recovery key cannot be all zeros")
	}

	return nil
}
