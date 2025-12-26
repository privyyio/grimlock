package types

// VersionMetadata contains metadata about a crypto version
type VersionMetadata struct {
	Version        string            `json:"version"`
	Algorithms     AlgorithmVersions `json:"algorithms"`
	Constants      interface{}       `json:"constants"`
	Deprecated     bool              `json:"deprecated,omitempty"`
	MigrationGuide string            `json:"migrationGuide,omitempty"`
}

// AlgorithmVersions specifies the cryptographic algorithms used in a version
type AlgorithmVersions struct {
	KeyExchange    string `json:"keyExchange"`    // e.g., "X25519"
	KeyDerivation  string `json:"keyDerivation"`  // e.g., "Argon2id-v1"
	Encryption     string `json:"encryption"`     // e.g., "AES-256-GCM"
	HKDF           string `json:"hkdf"`           // e.g., "HKDF-SHA512"
	RecoveryKey    string `json:"recoveryKey"`    // e.g., "256-bit-random"
	Serialization  string `json:"serialization"`  // e.g., "Base64"
}

// CompatibilityMatrix defines version compatibility
type CompatibilityMatrix map[string]map[string]bool
