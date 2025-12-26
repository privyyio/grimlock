package utils

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// EncodeBase64 encodes bytes to base64 string
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes base64 string to bytes
func DecodeBase64(encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	return data, nil
}

// EncodeHex encodes bytes to hex string
func EncodeHex(data []byte) string {
	return hex.EncodeToString(data)
}

// DecodeHex decodes hex string to bytes
func DecodeHex(encoded string) ([]byte, error) {
	data, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}
	return data, nil
}

// EncodeURLSafeBase64 encodes bytes to URL-safe base64 string
func EncodeURLSafeBase64(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// DecodeURLSafeBase64 decodes URL-safe base64 string to bytes
func DecodeURLSafeBase64(encoded string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode URL-safe base64: %w", err)
	}
	return data, nil
}
