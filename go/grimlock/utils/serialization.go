package utils

import (
	"encoding/json"
	"fmt"

	"github.com/privyy-io/grimlock/go/grimlock/types"
)

// SerializeKeyPair serializes a key pair to base64-encoded strings
func SerializeKeyPair(keyPair *types.KeyPair) *types.SerializedKeyPair {
	return &types.SerializedKeyPair{
		PrivateKey: EncodeBase64(keyPair.PrivateKey),
		PublicKey:  EncodeBase64(keyPair.PublicKey),
	}
}

// DeserializeKeyPair deserializes a base64-encoded key pair
func DeserializeKeyPair(serialized *types.SerializedKeyPair) (*types.KeyPair, error) {
	privateKey, err := DecodeBase64(serialized.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	publicKey, err := DecodeBase64(serialized.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return &types.KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// SerializeEncryptedPrivateKey serializes an encrypted private key to JSON
func SerializeEncryptedPrivateKey(encrypted *types.EncryptedPrivateKey) ([]byte, error) {
	serialized := map[string]string{
		"iv":         EncodeBase64(encrypted.IV),
		"tag":        EncodeBase64(encrypted.Tag),
		"ciphertext": EncodeBase64(encrypted.Ciphertext),
	}
	return json.Marshal(serialized)
}

// DeserializeEncryptedPrivateKey deserializes an encrypted private key from JSON
func DeserializeEncryptedPrivateKey(data []byte) (*types.EncryptedPrivateKey, error) {
	var serialized map[string]string
	if err := json.Unmarshal(data, &serialized); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted private key: %w", err)
	}

	iv, err := DecodeBase64(serialized["iv"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	tag, err := DecodeBase64(serialized["tag"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode tag: %w", err)
	}

	ciphertext, err := DecodeBase64(serialized["ciphertext"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	return &types.EncryptedPrivateKey{
		IV:         iv,
		Tag:        tag,
		Ciphertext: ciphertext,
	}, nil
}

// SerializeEncryptedMessage serializes an encrypted message to JSON
func SerializeEncryptedMessage(encrypted *types.EncryptedMessage) ([]byte, error) {
	serialized := map[string]string{
		"ephemeralPublicKey": EncodeBase64(encrypted.EphemeralPublicKey),
		"iv":                 EncodeBase64(encrypted.IV),
		"tag":                EncodeBase64(encrypted.Tag),
		"ciphertext":         EncodeBase64(encrypted.Ciphertext),
	}
	return json.Marshal(serialized)
}

// DeserializeEncryptedMessage deserializes an encrypted message from JSON
func DeserializeEncryptedMessage(data []byte) (*types.EncryptedMessage, error) {
	var serialized map[string]string
	if err := json.Unmarshal(data, &serialized); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted message: %w", err)
	}

	ephPubKey, err := DecodeBase64(serialized["ephemeralPublicKey"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ephemeral public key: %w", err)
	}

	iv, err := DecodeBase64(serialized["iv"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	tag, err := DecodeBase64(serialized["tag"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode tag: %w", err)
	}

	ciphertext, err := DecodeBase64(serialized["ciphertext"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	return &types.EncryptedMessage{
		EphemeralPublicKey: ephPubKey,
		IV:                 iv,
		Tag:                tag,
		Ciphertext:         ciphertext,
	}, nil
}
