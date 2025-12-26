package v1

import (
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// ComputeSharedSecret performs X25519 ECDH to compute a shared secret
func ComputeSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	if len(privateKey) != Constants.X25519PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
			Constants.X25519PrivateKeySize, len(privateKey))
	}
	if len(publicKey) != Constants.X25519PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: expected %d, got %d",
			Constants.X25519PublicKeySize, len(publicKey))
	}

	// Perform ECDH
	sharedSecret, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Check for low-order points (all-zero shared secret)
	if isAllZero(sharedSecret) {
		return nil, fmt.Errorf("ECDH resulted in low-order point (all-zero shared secret)")
	}

	return sharedSecret, nil
}

// isAllZero checks if a byte slice is all zeros
func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
