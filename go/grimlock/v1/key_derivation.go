package v1

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"github.com/privyy/grimlock/types"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// DerivePasscodeKey derives a key from a passcode using Argon2id
func DerivePasscodeKey(passcode string, params types.KdfParams) ([]byte, error) {
	if len(params.Salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}
	if len(passcode) == 0 {
		return nil, fmt.Errorf("passcode cannot be empty")
	}

	// Use provided parameters or defaults
	timeCost := params.Argon2Params.TimeCost
	memoryCost := params.Argon2Params.MemoryCost
	parallelism := params.Argon2Params.Parallelism

	if timeCost == 0 {
		timeCost = Constants.DefaultArgon2Params.TimeCost
	}
	if memoryCost == 0 {
		memoryCost = Constants.DefaultArgon2Params.MemoryCost
	}
	if parallelism == 0 {
		parallelism = Constants.DefaultArgon2Params.Parallelism
	}

	// Derive key using Argon2id
	key := argon2.IDKey(
		[]byte(passcode),
		params.Salt,
		timeCost,
		memoryCost,
		parallelism,
		uint32(Constants.AESKeySize),
	)

	return key, nil
}

// DeriveRecoveryKey derives a key from recovery key bytes using HKDF-SHA512
func DeriveRecoveryKey(recoveryKeyBytes []byte) ([]byte, error) {
	if len(recoveryKeyBytes) != Constants.RecoveryKeySize {
		return nil, fmt.Errorf("invalid recovery key size: expected %d, got %d",
			Constants.RecoveryKeySize, len(recoveryKeyBytes))
	}

	// Use HKDF-SHA512 to derive encryption key from recovery key
	salt := []byte(Constants.HKDFSaltRecovery)
	info := []byte(Constants.HKDFInfoRecoveryDerivation)

	return deriveKeyHKDF(recoveryKeyBytes, salt, info, Constants.AESKeySize)
}

// DeriveMessageKey derives a symmetric key for message encryption from ECDH shared secret
func DeriveMessageKey(sharedSecret []byte, context types.MessageContext) ([]byte, error) {
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("invalid shared secret size: expected 32, got %d", len(sharedSecret))
	}

	// Use HKDF-SHA512 to derive message encryption key
	salt := []byte(Constants.HKDFSaltEncryption)
	
	// Combine conversation ID and message ID as info parameter
	info := []byte(fmt.Sprintf("%s%s||%s",
		Constants.HKDFInfoMessageKey,
		context.ConversationID,
		context.MessageID))

	return deriveKeyHKDF(sharedSecret, salt, info, Constants.AESKeySize)
}

// deriveKeyHKDF performs HKDF-SHA512 key derivation
func deriveKeyHKDF(ikm, salt, info []byte, keyLen int) ([]byte, error) {
	hkdfReader := hkdf.New(sha512.New, ikm, salt, info)
	
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}

	return key, nil
}

// GenerateSalt generates a random salt for key derivation
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, Constants.KDFSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// GenerateDefaultKdfParams generates default KDF parameters with a new random salt
func GenerateDefaultKdfParams() (types.KdfParams, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return types.KdfParams{}, err
	}

	return types.KdfParams{
		Salt:         salt,
		Argon2Params: Constants.DefaultArgon2Params,
	}, nil
}
