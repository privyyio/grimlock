package types

// KeyPair represents an X25519 key pair
type KeyPair struct {
	PrivateKey []byte `json:"privateKey"`
	PublicKey  []byte `json:"publicKey"`
}

// SerializedKeyPair represents a base64-encoded key pair
type SerializedKeyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

// EncryptedPrivateKey represents an encrypted private key with AES-GCM
type EncryptedPrivateKey struct {
	IV         []byte `json:"iv"`
	Tag        []byte `json:"tag"`
	Ciphertext []byte `json:"ciphertext"`
}

// MessagePayload represents the plaintext message payload
type MessagePayload struct {
	UserMessage       string                 `json:"userMessage"`
	AssistantResponse string                 `json:"assistantResponse"`
	OptionalContext   map[string]interface{} `json:"optionalContext,omitempty"`
}

// EncryptedMessage represents an encrypted message stored in the database
type EncryptedMessage struct {
	EphemeralPublicKey []byte `json:"ephemeralPublicKey"`
	IV                 []byte `json:"iv"`
	Tag                []byte `json:"tag"`
	Ciphertext         []byte `json:"ciphertext"`
}

// MessageContext provides context for message encryption/decryption
type MessageContext struct {
	ConversationID string `json:"conversationId"`
	MessageID      string `json:"messageId"`
}

// KdfParams contains parameters for Argon2id key derivation
type KdfParams struct {
	Salt         []byte       `json:"salt"`
	Argon2Params Argon2Params `json:"argon2Params"`
}

// Argon2Params contains specific Argon2id parameters
type Argon2Params struct {
	TimeCost    uint32 `json:"timeCost"`    // Number of iterations
	MemoryCost  uint32 `json:"memoryCost"`  // Memory in KiB
	Parallelism uint8  `json:"parallelism"` // Number of threads
}

// RecoveryKey represents a recovery key with mnemonic phrase
type RecoveryKey struct {
	Key      []byte `json:"key"`
	Mnemonic string `json:"mnemonic,omitempty"` // Optional BIP39 mnemonic
}

// HKDFParams contains parameters for HKDF key derivation
type HKDFParams struct {
	Salt []byte
	Info []byte
}
