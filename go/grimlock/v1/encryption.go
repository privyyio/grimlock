package v1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"

	"github.com/privyy/grimlock/types"
)

// EncryptPrivateKey encrypts a private key using AES-256-GCM
func EncryptPrivateKey(privateKey, encryptionKey, aad []byte) (*types.EncryptedPrivateKeyV1, error) {
	if len(privateKey) != Constants.X25519PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
			Constants.X25519PrivateKeySize, len(privateKey))
	}
	if len(encryptionKey) != Constants.AESKeySize {
		return nil, fmt.Errorf("invalid encryption key size: expected %d, got %d",
			Constants.AESKeySize, len(encryptionKey))
	}

	// Generate random IV
	iv := make([]byte, Constants.GCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Encrypt (Seal combines ciphertext and tag)
	ciphertextWithTag := gcm.Seal(nil, iv, privateKey, aad)

	// Split ciphertext and tag
	tagStart := len(ciphertextWithTag) - Constants.GCMTagSize
	ciphertext := ciphertextWithTag[:tagStart]
	tag := ciphertextWithTag[tagStart:]

	return types.NewEncryptedPrivateKeyV1(iv, tag, ciphertext), nil
}

// DecryptPrivateKey decrypts a private key using AES-256-GCM
func DecryptPrivateKey(encrypted *types.EncryptedPrivateKey, encryptionKey, aad []byte) ([]byte, error) {
	if len(encryptionKey) != Constants.AESKeySize {
		return nil, fmt.Errorf("invalid encryption key size: expected %d, got %d",
			Constants.AESKeySize, len(encryptionKey))
	}
	if len(encrypted.IV) != Constants.GCMNonceSize {
		return nil, fmt.Errorf("invalid IV size: expected %d, got %d",
			Constants.GCMNonceSize, len(encrypted.IV))
	}
	if len(encrypted.Tag) != Constants.GCMTagSize {
		return nil, fmt.Errorf("invalid tag size: expected %d, got %d",
			Constants.GCMTagSize, len(encrypted.Tag))
	}

	// Create AES cipher
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Combine ciphertext and tag for GCM Open
	ciphertextWithTag := append(encrypted.Ciphertext, encrypted.Tag...)

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, encrypted.IV, ciphertextWithTag, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (invalid key or tampered data): %w", err)
	}

	return plaintext, nil
}

// EncryptMessage encrypts a message payload using ephemeral key ECDH + AES-256-GCM
func EncryptMessage(payload types.MessagePayload, userPublicKey []byte, context types.MessageContext) (*types.EncryptedMessageV1, error) {
	if len(userPublicKey) != Constants.X25519PublicKeySize {
		return nil, fmt.Errorf("invalid user public key size: expected %d, got %d",
			Constants.X25519PublicKeySize, len(userPublicKey))
	}

	// 1. Generate ephemeral key pair
	ephemeralKeyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key pair: %w", err)
	}
	defer SecureErase(ephemeralKeyPair.PrivateKey) // Erase ephemeral private key after use

	// 2. Compute shared secret via ECDH
	sharedSecret, err := ComputeSharedSecret(ephemeralKeyPair.PrivateKey, userPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	defer SecureErase(sharedSecret) // Erase shared secret after use

	// 3. Derive message encryption key
	msgKey, err := DeriveMessageKey(sharedSecret, context)
	if err != nil {
		return nil, fmt.Errorf("failed to derive message key: %w", err)
	}
	defer SecureErase(msgKey) // Erase message key after use

	// 4. Serialize payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize payload: %w", err)
	}

	// 5. Encrypt payload
	iv := make([]byte, Constants.GCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	block, err := aes.NewCipher(msgKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create metadata as AAD (additional authenticated data)
	metadata := createMetadataAAD(context)

	// Encrypt with AAD
	ciphertextWithTag := gcm.Seal(nil, iv, payloadBytes, metadata)

	// Split ciphertext and tag
	tagStart := len(ciphertextWithTag) - Constants.GCMTagSize
	ciphertext := ciphertextWithTag[:tagStart]
	tag := ciphertextWithTag[tagStart:]

	return types.NewEncryptedMessageV1(ephemeralKeyPair.PublicKey, iv, tag, ciphertext), nil
}

// DecryptMessage decrypts a message using user private key and ECDH
func DecryptMessage(encrypted *types.EncryptedMessage, userPrivateKey []byte, context types.MessageContext, metadata []byte) (*types.MessagePayload, error) {
	if len(userPrivateKey) != Constants.X25519PrivateKeySize {
		return nil, fmt.Errorf("invalid user private key size: expected %d, got %d",
			Constants.X25519PrivateKeySize, len(userPrivateKey))
	}
	if len(encrypted.EphemeralPublicKey) != Constants.X25519PublicKeySize {
		return nil, fmt.Errorf("invalid ephemeral public key size: expected %d, got %d",
			Constants.X25519PublicKeySize, len(encrypted.EphemeralPublicKey))
	}
	if len(encrypted.IV) != Constants.GCMNonceSize {
		return nil, fmt.Errorf("invalid IV size: expected %d, got %d",
			Constants.GCMNonceSize, len(encrypted.IV))
	}
	if len(encrypted.Tag) != Constants.GCMTagSize {
		return nil, fmt.Errorf("invalid tag size: expected %d, got %d",
			Constants.GCMTagSize, len(encrypted.Tag))
	}

	// 1. Compute shared secret via ECDH
	sharedSecret, err := ComputeSharedSecret(userPrivateKey, encrypted.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	defer SecureErase(sharedSecret)

	// 2. Derive message encryption key
	msgKey, err := DeriveMessageKey(sharedSecret, context)
	if err != nil {
		return nil, fmt.Errorf("failed to derive message key: %w", err)
	}
	defer SecureErase(msgKey)

	// 3. Decrypt payload
	block, err := aes.NewCipher(msgKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Use metadata as AAD if not provided
	if metadata == nil {
		metadata = createMetadataAAD(context)
	}

	// Combine ciphertext and tag
	ciphertextWithTag := append(encrypted.Ciphertext, encrypted.Tag...)

	// Decrypt and verify
	payloadBytes, err := gcm.Open(nil, encrypted.IV, ciphertextWithTag, metadata)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (invalid key or tampered data): %w", err)
	}

	// 4. Deserialize payload
	var payload types.MessagePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to deserialize payload: %w", err)
	}

	return &payload, nil
}

// createMetadataAAD creates metadata for use as AAD in GCM
func createMetadataAAD(context types.MessageContext) []byte {
	return []byte(fmt.Sprintf("%s||%s", context.ConversationID, context.MessageID))
}
