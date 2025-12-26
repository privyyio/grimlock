package types

// V1 version-tagged types for type safety

// KeyPairV1 represents a v1 X25519 key pair with version tag
type KeyPairV1 struct {
	KeyPair
	Version string `json:"_version"`
}

// EncryptedPrivateKeyV1 represents a v1 encrypted private key with version tag
type EncryptedPrivateKeyV1 struct {
	EncryptedPrivateKey
	Version string `json:"_version"`
}

// EncryptedMessageV1 represents a v1 encrypted message with version tag
type EncryptedMessageV1 struct {
	EncryptedMessage
	Version string `json:"_version"`
}

// MessagePayloadV1 represents a v1 message payload with version tag
type MessagePayloadV1 struct {
	MessagePayload
	Version string `json:"_version"`
}

// NewKeyPairV1 creates a new v1 key pair with version tag
func NewKeyPairV1(privateKey, publicKey []byte) *KeyPairV1 {
	return &KeyPairV1{
		KeyPair: KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		},
		Version: "v1",
	}
}

// NewEncryptedPrivateKeyV1 creates a new v1 encrypted private key with version tag
func NewEncryptedPrivateKeyV1(iv, tag, ciphertext []byte) *EncryptedPrivateKeyV1 {
	return &EncryptedPrivateKeyV1{
		EncryptedPrivateKey: EncryptedPrivateKey{
			IV:         iv,
			Tag:        tag,
			Ciphertext: ciphertext,
		},
		Version: "v1",
	}
}

// NewEncryptedMessageV1 creates a new v1 encrypted message with version tag
func NewEncryptedMessageV1(ephPubKey, iv, tag, ciphertext []byte) *EncryptedMessageV1 {
	return &EncryptedMessageV1{
		EncryptedMessage: EncryptedMessage{
			EphemeralPublicKey: ephPubKey,
			IV:                 iv,
			Tag:                tag,
			Ciphertext:         ciphertext,
		},
		Version: "v1",
	}
}
