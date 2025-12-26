# Grimlock Crypto Module (Go Implementation)

Versioned cryptographic operations module for server-side operations, implementing the Okara whitepaper encryption-at-rest protocol.

## Overview

Grimlock provides a versioned API for cryptographic operations including:
- X25519 key pair generation and ECDH
- Argon2id key derivation from passcodes
- AES-256-GCM encryption/decryption
- HKDF-SHA512 for key derivation
- Recovery key generation and management

This Go implementation mirrors the client-side TypeScript implementation and must stay in sync for interoperability.

## Architecture

```
grimlock/
├── types/              # Type definitions
│   ├── common.go       # Shared types across versions
│   ├── v1.go           # v1 version-tagged types
│   └── version.go      # Version metadata types
├── v1/                 # Version 1 implementation
│   ├── constants.go    # v1 cryptographic constants
│   ├── key_generation.go
│   ├── key_derivation.go
│   ├── encryption.go
│   ├── ecdh.go
│   ├── recovery_key.go
│   ├── utils.go
│   └── index.go        # v1 API exports
├── v2/                 # Version 2 placeholder
│   └── index.go
├── utils/              # Utilities
│   ├── encoding.go
│   ├── serialization.go
│   └── memory_security.go
├── version_manager.go  # Version registry and metadata
├── version_detection.go # Version detection utilities
└── grimlock.go         # Main entry point

```

## Installation

```bash
go get github.com/privyy-io/grimlock/go/grimlock
```

Required dependencies (already in go.mod):
- `golang.org/x/crypto` - For Argon2id, Curve25519, and HKDF

## Usage

### Basic Usage (Default/Latest Version)

```go
package main

import (
    "fmt"
    "github.com/privyy-io/grimlock/go/grimlock"
    "github.com/privyy-io/grimlock/go/grimlock/types"
)

func main() {
    // Generate key pair
    keyPair, err := grimlock.GenerateKeyPair()
    if err != nil {
        panic(err)
    }

    // Generate KDF parameters
    kdfParams, err := grimlock.GenerateDefaultKdfParams()
    if err != nil {
        panic(err)
    }

    // Derive passcode key
    passcodeKey, err := grimlock.DerivePasscodeKey("user-passcode", kdfParams)
    if err != nil {
        panic(err)
    }
    defer grimlock.Default.SecureErase(passcodeKey)

    // Encrypt private key
    encrypted, err := grimlock.EncryptPrivateKey(
        keyPair.PrivateKey,
        passcodeKey,
        []byte("user-id"),
    )
    if err != nil {
        panic(err)
    }

    fmt.Printf("Encrypted private key: %+v\n", encrypted)
}
```

### Explicit Version Usage

```go
import (
    "github.com/privyy-io/grimlock/go/grimlock/v1"
    "github.com/privyy-io/grimlock/go/grimlock/types"
)

func main() {
    // Use v1 explicitly
    api := v1.V1
    keyPair, err := api.GenerateKeyPair()
    if err != nil {
        panic(err)
    }

    // Access v1 constants
    fmt.Printf("AES Key Size: %d\n", v1.Constants.AESKeySize)
}
```

### Version Manager

```go
import "github.com/privyy-io/grimlock/go/grimlock"

func main() {
    manager := grimlock.GetVersionManager()
    
    // Get latest version
    latest := manager.GetLatestVersion() // "v1"
    
    // Get version metadata
    v1Meta, err := manager.GetVersion("v1")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Algorithm: %s\n", v1Meta.Algorithms.KeyExchange)
    
    // Check compatibility
    compatible := manager.IsCompatible("v1", "v1") // true
}
```

### Server-Side Message Encryption (Algorithm C)

This is the key server-side operation for encrypting messages before storage:

```go
import (
    "github.com/privyy-io/grimlock/go/grimlock"
    "github.com/privyy-io/grimlock/go/grimlock/types"
)

func encryptMessageForStorage(
    userMessage string,
    assistantResponse string,
    userPublicKey []byte,
    conversationID string,
    messageID string,
) (*types.EncryptedMessageV1, error) {
    // Create payload
    payload := types.MessagePayload{
        UserMessage:       userMessage,
        AssistantResponse: assistantResponse,
        OptionalContext:   map[string]interface{}{
            "timestamp": time.Now().Unix(),
        },
    }

    // Create context
    context := types.MessageContext{
        ConversationID: conversationID,
        MessageID:      messageID,
    }

    // Encrypt message (server creates ephemeral keys)
    encrypted, err := grimlock.EncryptMessage(payload, userPublicKey, context)
    if err != nil {
        return nil, err
    }

    // Note: Ephemeral private key is automatically erased after encryption
    // Store encrypted.EphemeralPublicKey, encrypted.IV, encrypted.Tag, encrypted.Ciphertext

    return encrypted, nil
}
```

### Version Detection

```go
import "github.com/privyy-io/grimlock/go/grimlock"

func decryptWithAutoVersion(encryptedData interface{}, privateKey []byte) error {
    // Auto-detect version
    version, err := grimlock.DetectVersion(encryptedData)
    if err != nil {
        return err
    }

    // Get appropriate API version
    crypto, err := grimlock.NewWithVersion(version)
    if err != nil {
        return err
    }

    // Use the correct version for decryption
    // ... decrypt using crypto API
    return nil
}
```

## API Reference

### Key Generation

- `GenerateKeyPair() (*types.KeyPairV1, error)` - Generate X25519 key pair
- `ValidateKeyPair(*types.KeyPair) error` - Validate key pair

### Key Derivation

- `DerivePasscodeKey(passcode string, params types.KdfParams) ([]byte, error)` - Derive key from passcode using Argon2id
- `DeriveRecoveryKey(recoveryKeyBytes []byte) ([]byte, error)` - Derive key from recovery key using HKDF-SHA512
- `GenerateSalt() ([]byte, error)` - Generate random salt
- `GenerateDefaultKdfParams() (types.KdfParams, error)` - Generate default KDF parameters

### Private Key Operations

- `EncryptPrivateKey(privateKey, encryptionKey, aad []byte) (*types.EncryptedPrivateKeyV1, error)` - Encrypt private key
- `DecryptPrivateKey(encrypted *types.EncryptedPrivateKey, encryptionKey, aad []byte) ([]byte, error)` - Decrypt private key

### Message Operations

- `EncryptMessage(payload types.MessagePayload, userPublicKey []byte, context types.MessageContext) (*types.EncryptedMessageV1, error)` - Encrypt message payload
- `DecryptMessage(encrypted *types.EncryptedMessage, userPrivateKey []byte, context types.MessageContext, metadata []byte) (*types.MessagePayload, error)` - Decrypt message payload

### Recovery Key

- `GenerateRecoveryKey() (*types.RecoveryKey, error)` - Generate recovery key
- `EncryptPrivateKeyWithRecoveryKey(privateKey, recoveryKey, aad []byte) (*types.EncryptedPrivateKeyV1, error)` - Encrypt with recovery key
- `DecryptPrivateKeyWithRecoveryKey(encrypted *types.EncryptedPrivateKey, recoveryKey, aad []byte) ([]byte, error)` - Decrypt with recovery key

### ECDH

- `ComputeSharedSecret(privateKey, publicKey []byte) ([]byte, error)` - Perform X25519 ECDH

### Utilities

- `SerializeKeyPair(*types.KeyPair) *types.SerializedKeyPair` - Serialize key pair to Base64
- `DeserializeKeyPair(*types.SerializedKeyPair) (*types.KeyPair, error)` - Deserialize key pair from Base64
- `SecureErase([]byte)` - Securely erase sensitive data

## Constants

All constants use "grimlock" prefix:

- `grimlock-encryption-salt` - HKDF salt for message encryption
- `grimlock-recovery-salt` - HKDF salt for recovery key derivation
- `grimlock-message-key` - HKDF info for message key derivation
- `grimlock-recovery-key-derivation` - HKDF info for recovery key derivation
- `grimlock-dual-encryption` - HKDF info for dual encryption
- `grimlock-default-pepper` - Default pepper for passcode HMAC

### V1 Constants

```go
v1.Constants.X25519PrivateKeySize  // 32 bytes
v1.Constants.X25519PublicKeySize   // 32 bytes
v1.Constants.AESKeySize            // 32 bytes (AES-256)
v1.Constants.GCMNonceSize          // 12 bytes
v1.Constants.GCMTagSize            // 16 bytes
v1.Constants.RecoveryKeySize       // 32 bytes

// Default Argon2id parameters
v1.Constants.DefaultArgon2Params.TimeCost     // 4 iterations
v1.Constants.DefaultArgon2Params.MemoryCost   // 128 MiB
v1.Constants.DefaultArgon2Params.Parallelism  // 2 threads
```

## Versioning

The module uses namespace-based versioning:
- `v1` - Current stable version
- `v2` - Future version (placeholder)

Each version maintains backward compatibility for decryption operations while allowing new algorithms for encryption.

## Security Notes

1. **Memory Security**: The module attempts to zero out sensitive data using `SecureErase()`. While Go's garbage collector makes complete memory erasure difficult, we zero memory we control.

2. **Random Number Generation**: Uses Go's `crypto/rand` for cryptographically secure random number generation.

3. **Key Management**: Private keys should never be logged or stored in plaintext. Always use encrypted storage.

4. **Ephemeral Keys**: Server-side message encryption automatically generates and erases ephemeral private keys after use.

5. **ECDH Validation**: The implementation checks for low-order points in ECDH operations.

## Algorithm Sequence (Okara Whitepaper)

This implementation follows the Okara whitepaper protocol:

### Algorithm A - Account Creation (Server-side)
1. Client generates key pair and encrypts private key
2. Server receives and stores: `UserPublicKey`, `EncUserPrivateKey`, `KdfSalt`, `KdfParams`

### Algorithm C - Send Message + Encrypt Before Storage (Server-side)
1. Server processes plaintext message for model inference
2. Server generates ephemeral key pair
3. Server computes ECDH shared secret with user's public key
4. Server derives message encryption key via HKDF
5. Server encrypts payload with AES-256-GCM
6. **Server erases ephemeral private key** (critical for security)
7. Server stores: `EphPub`, `IV`, `Ciphertext`, `Tag`, `Metadata`

### Algorithm D - Retrieve & Decrypt History (Client-side only)
Client decrypts stored ciphertext locally using their long-term private key.

## Synchronization with Client Implementation

This Go implementation must stay in sync with the client-side TypeScript implementation:

1. **Constants**: All constants must match exactly
2. **HKDF Info Strings**: Must use identical strings for key derivation
3. **AAD Construction**: Metadata AAD format must match
4. **Serialization**: Base64 encoding/decoding must be compatible
5. **Version Tags**: Version detection must work across implementations

## Testing

Run tests with:

```bash
go test ./grimlock/...
```

## License

Part of privyy project.

## References

- [ALGORITHM_SEQUENCE.md](../grimlock/ALGORITHM_SEQUENCE.md) - Okara whitepaper algorithm sequence
- [IMPLEMENTATION_SUMMARY.md](../grimlock/IMPLEMENTATION_SUMMARY.md) - Client-side implementation summary
- [versioned_crypto_module_apis_c08702c2.plan.md](../grimlock/versioned_crypto_module_apis_c08702c2.plan.md) - Implementation plan
