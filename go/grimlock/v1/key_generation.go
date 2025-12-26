package v1

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/privyy/grimlock/types"
	"golang.org/x/crypto/curve25519"
)

// GenerateKeyPair generates a new X25519 key pair
func GenerateKeyPair() (*types.KeyPairV1, error) {
	// Generate random private key
	privateKey := make([]byte, Constants.X25519PrivateKeySize)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Derive public key from private key
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	return types.NewKeyPairV1(privateKey, publicKey), nil
}

// ValidateKeyPair validates that a key pair is well-formed
func ValidateKeyPair(keyPair *types.KeyPair) error {
	if len(keyPair.PrivateKey) != Constants.X25519PrivateKeySize {
		return fmt.Errorf("invalid private key size: expected %d, got %d",
			Constants.X25519PrivateKeySize, len(keyPair.PrivateKey))
	}
	if len(keyPair.PublicKey) != Constants.X25519PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d, got %d",
			Constants.X25519PublicKeySize, len(keyPair.PublicKey))
	}

	// Verify that public key matches private key
	derivedPublicKey, err := curve25519.X25519(keyPair.PrivateKey, curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("failed to derive public key for validation: %w", err)
	}

	// Compare derived public key with provided public key
	if !bytesEqual(derivedPublicKey, keyPair.PublicKey) {
		return fmt.Errorf("public key does not match private key")
	}

	return nil
}

// bytesEqual performs constant-time comparison of byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
