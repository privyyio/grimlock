// Package grimlock provides versioned end-to-end encryption primitives for
// securing private keys and messages using modern cryptographic algorithms.
//
// # Overview
//
// Grimlock implements the Okara cryptographic protocol, which combines:
//   - X25519 Elliptic-Curve Diffie-Hellman (ECDH) for key exchange
//   - Argon2id for passcode-based key derivation
//   - HKDF-SHA512 for recovery key derivation
//   - AES-256-GCM for authenticated encryption
//
// The library is designed for cross-platform compatibility and ships with
// identical implementations in Go and TypeScript.
//
// # Quick Start
//
//	// Generate a key pair
//	keyPair, err := grimlock.GenerateKeyPair()
//
//	// Derive an encryption key from a passcode
//	kdfParams, _ := grimlock.GenerateDefaultKdfParams()
//	encKey, err := grimlock.DerivePasscodeKey("my-passcode", kdfParams)
//
//	// Encrypt the private key for storage
//	encrypted, err := grimlock.EncryptPrivateKey(keyPair.PrivateKey, encKey, aad)
//
// # Versioning
//
// All encrypted outputs carry a _version field. Use [NewWithVersion] to target
// a specific version explicitly, or use [Default] / [New] to always get the
// latest version (currently v1).
//
// # Official Documentation
//
// Full guides, algorithm specifications, and cross-platform examples are
// available at https://privyyio.github.com/grimlock
package grimlock
