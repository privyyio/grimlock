# Grimlock 🔐

**Versioned Cryptographic Operations Module for Privyy.io**

Grimlock is a robust, cross-platform cryptographic library that provides secure key management, message encryption, and recovery mechanisms for the Privyy.io platform. It features identical implementations in both Go and TypeScript, ensuring seamless interoperability across different parts of your stack.

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)]()
[![Go Version](https://img.shields.io/badge/go-%3E%3D1.21-blue)]()
[![Node Version](https://img.shields.io/badge/node-%3E%3D18-green)]()
[![Cross-Compatible](https://img.shields.io/badge/cross--compatible-100%25-success)]()

## 🌟 Features

- **🔒 End-to-End Encryption**: Secure message encryption using X25519 ECDH + AES-256-GCM
- **🔑 Key Management**: Robust key generation, derivation, and encryption
- **🔄 Recovery Keys**: Secure account recovery with optional BIP39 mnemonic support
- **🌐 Cross-Platform**: Identical implementations in Go and TypeScript
- **✅ Fully Tested**: Comprehensive cross-compatibility test suite
- **📦 Version Support**: Built-in versioning for future protocol upgrades
- **🛡️ Memory Security**: Secure erasure of sensitive data after use

## 📋 Table of Contents

- [Architecture](#architecture)
- [Implementations](#implementations)
- [Quick Start](#quick-start)
- [Cryptographic Operations](#cryptographic-operations)
- [Cross-Compatibility](#cross-compatibility)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

## 🏗️ Architecture

Grimlock uses a versioned architecture to support protocol evolution:

```
grimlock/
├── go/grimlock/              # Go implementation
│   ├── v1/                   # Version 1 implementation
│   ├── types/                # Type definitions
│   ├── utils/                # Utilities
│   └── grimlock.go          # Main API
│
├── typescript/grimlock/      # TypeScript implementation
│   ├── versions/v1/          # Version 1 implementation
│   ├── types/                # Type definitions
│   ├── utils/                # Utilities
│   └── index.ts              # Main API
│
└── cross-compatibility-testing/  # Test suite
    ├── go-generator/         # Generates test data with Go
    ├── go-verifier/          # Verifies TS data with Go
    ├── ts-generator/         # Generates test data with TS
    └── ts-verifier/          # Verifies Go data with TS
```

## 🚀 Implementations

### Go Implementation

**Location**: `go/grimlock/`

```go
import "github.com/privyyio/grimlock"

// Generate a new key pair
keyPair, err := grimlock.GenerateKeyPair()

// Derive key from passcode
params, _ := grimlock.GenerateDefaultKdfParams()
key, err := grimlock.DerivePasscodeKey("MySecurePasscode", params)

// Encrypt a message
encrypted, err := grimlock.EncryptMessage(payload, recipientPublicKey, context)

// Decrypt a message
payload, err := grimlock.DecryptMessage(encrypted, privateKey, context, nil)
```

**See**: [Go README](go/grimlock/README.md)

### TypeScript Implementation

**Location**: `typescript/grimlock/`

```typescript
import grimlock from '@/lib/grimlock';

// Generate a new key pair
const keyPair = await grimlock.generateKeyPair();

// Derive key from passcode
const params = { salt, argon2Params: { timeCost: 4, memoryCost: 131072, parallelism: 2 } };
const key = await grimlock.derivePasscodeKey('MySecurePasscode', params);

// Encrypt a message
const encrypted = await grimlock.encryptMessage(payload, recipientPublicKey, context);

// Decrypt a message
const payload = await grimlock.decryptMessage(encrypted, privateKey, context);
```

**See**: [TypeScript README](typescript/grimlock/README.md)

## 🎯 Quick Start

### Prerequisites

**Go Implementation:**
- Go 1.21 or higher
- Dependencies: `golang.org/x/crypto`

**TypeScript Implementation:**
- Node.js 18+
- Dependencies: `argon2`, `@noble/curves`

### Installation

#### Go

```bash
cd go/grimlock
go get github.com/privyyio/grimlock
```

#### TypeScript

```bash
cd typescript/grimlock
npm install
```

### Running Tests

#### Go Tests

```bash
cd go/grimlock
go test -v
```

#### TypeScript Tests

```bash
cd typescript/grimlock
npm test
```

#### Cross-Compatibility Tests

```bash
cd cross-compatibility-testing
./run-tests.sh
```

**Result**: ✅ All tests passing (7/7 in each direction)

## 🔐 Cryptographic Operations

### 1. Key Generation

Generate X25519 key pairs for ECDH:

```typescript
// TypeScript
const keyPair = await grimlock.generateKeyPair();
// Returns: { privateKey: Uint8Array(32), publicKey: Uint8Array(32) }
```

```go
// Go
keyPair, err := grimlock.GenerateKeyPair()
// Returns: KeyPair with 32-byte private and public keys
```

### 2. Key Derivation

#### Passcode-Based Key Derivation (Argon2id)

```typescript
const params = {
  salt: crypto.getRandomValues(new Uint8Array(32)),
  argon2Params: {
    timeCost: 4,        // iterations
    memoryCost: 131072, // 128MB in KB
    parallelism: 2      // threads
  }
};
const derivedKey = await grimlock.derivePasscodeKey('password', params);
```

#### Recovery Key Derivation (HKDF-SHA512)

```typescript
const recoveryKey = await grimlock.generateRecoveryKey();
const encryptionKey = await grimlock.deriveRecoveryKey(recoveryKey.raw);
```

### 3. Private Key Encryption

Encrypt private keys using AES-256-GCM:

```typescript
const encrypted = await grimlock.encryptPrivateKey(
  privateKey,
  encryptionKey,
  aad  // Additional Authenticated Data (e.g., user email)
);
```

### 4. Message Encryption

End-to-end encrypted messaging using ephemeral ECDH:

```typescript
const payload = {
  userMessage: 'Hello!',
  assistantResponse: 'Hi there!',
  context: { timestamp: '...' }
};

const context = {
  conversationId: 'conv-123',
  messageId: 'msg-456'
};

// Encrypt
const encrypted = await grimlock.encryptMessage(
  payload,
  recipientPublicKey,
  context
);

// Decrypt
const decrypted = await grimlock.decryptMessage(
  encrypted,
  recipientPrivateKey,
  context
);
```

**Flow:**
1. Generate ephemeral key pair
2. Compute ECDH shared secret
3. Derive message key using HKDF with context
4. Encrypt with AES-256-GCM using context as AAD
5. Securely erase ephemeral keys

### 5. Recovery Keys

Generate secure recovery keys with optional mnemonic:

```typescript
const recoveryKey = await grimlock.generateRecoveryKey();
// Returns: { raw: Uint8Array(32), base64: string, mnemonic?: string }

// Use for encryption
const encryptionKey = await grimlock.deriveRecoveryKey(recoveryKey.raw);
```

## ✅ Cross-Compatibility

Grimlock includes a comprehensive cross-compatibility test suite that ensures both implementations work together seamlessly:

```bash
cd cross-compatibility-testing
./run-tests.sh
```

**Test Coverage:**
- ✅ Passcode Key Derivation (Argon2id)
- ✅ Recovery Key Derivation (HKDF-SHA512)
- ✅ Private Key Encryption/Decryption (AES-256-GCM)
- ✅ Message Encryption/Decryption (ECDH + AES-256-GCM)
- ✅ ECDH Shared Secret Computation (X25519)
- ✅ Bidirectional Verification (Go→TS and TS→Go)

**Results:**
```
╔════════════════════════════════════════════════════════════╗
║  ✓ All cross-compatibility tests passed!                  ║
╚════════════════════════════════════════════════════════════╝

Total Tests:  4
Passed:       4
Failed:       0

Go → TypeScript: 7/7 tests passing
TypeScript → Go: 7/7 tests passing
```

**See**: [Cross-Compatibility README](cross-compatibility-testing/README.md)

## 🔒 Security Considerations

### Cryptographic Primitives

- **X25519**: Elliptic curve Diffie-Hellman
- **AES-256-GCM**: Authenticated encryption with 256-bit keys
- **Argon2id**: Memory-hard password hashing
- **HKDF-SHA512**: Key derivation function
- **Secure Random**: Cryptographically secure random number generation

### Best Practices

1. **Key Storage**: Never store private keys in plain text
2. **AAD Usage**: Always use Additional Authenticated Data for context
3. **Key Erasure**: Sensitive keys are securely erased after use
4. **Version Detection**: Encrypted data includes version markers
5. **Context Binding**: Messages are bound to conversation/message IDs

### Memory Security

Both implementations attempt to securely erase sensitive data:

```typescript
// TypeScript (best effort)
privateKey.fill(0);
```

```go
// Go (uses memguard-like techniques)
utils.SecureErase(privateKey)
```

## 🛠️ Development

### Project Structure

```
grimlock/
├── go/
│   └── grimlock/
│       ├── v1/              # V1 implementation
│       │   ├── constants.go
│       │   ├── ecdh.go
│       │   ├── encryption.go
│       │   ├── key_derivation.go
│       │   ├── key_generation.go
│       │   └── recovery_key.go
│       ├── types/           # Type definitions
│       ├── utils/           # Utilities
│       └── grimlock.go      # Main API
│
├── typescript/
│   └── grimlock/
│       ├── versions/v1/     # V1 implementation
│       │   ├── constants.ts
│       │   ├── ecdh.ts
│       │   ├── encryption.ts
│       │   ├── key-derivation.ts
│       │   ├── key-generation.ts
│       │   └── recovery-key.ts
│       ├── types/           # Type definitions
│       ├── utils/           # Utilities
│       └── index.ts         # Main API
│
└── cross-compatibility-testing/
    ├── go-generator/        # Go test data generator
    ├── go-verifier/         # Go verification
    ├── ts-generator/        # TS test data generator
    ├── ts-verifier/         # TS verification
    └── run-tests.sh         # Master test runner
```

### Adding New Features

1. Implement in both Go and TypeScript
2. Update type definitions
3. Add tests to both implementations
4. Add cross-compatibility tests
5. Update documentation

### CI/CD Integration

```yaml
name: Grimlock Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Set up Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Run Go tests
        run: cd go/grimlock && go test -v
      
      - name: Run TypeScript tests
        run: cd typescript/grimlock && npm install && npm test
      
      - name: Run cross-compatibility tests
        run: cd cross-compatibility-testing && ./run-tests.sh
```

## 🤝 Contributing

We welcome contributions! Please see [AGENTS.md](AGENTS.md) for guidelines on working with this codebase, especially when using AI assistants.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make changes in **both** Go and TypeScript implementations
4. Add tests for new features
5. Run cross-compatibility tests
6. Submit a pull request

### Code Standards

- **Go**: Follow standard Go conventions (`gofmt`, `golint`)
- **TypeScript**: Follow the existing style (ESLint config)
- **Tests**: All new features must have tests
- **Documentation**: Update README files as needed

## 📄 License

This software is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).

**Free for personal and non-commercial use.** Commercial use requires a separate license from Privyy. Contact [info@privyy.io](mailto:info@privyy.io) for commercial licensing.

## 🔗 Related Projects

- [Privyy.io](https://privyy.io) - The platform using Grimlock
- [@noble/curves](https://github.com/paulmillr/noble-curves) - TypeScript elliptic curves
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) - Go crypto library

## 📞 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- See [AGENTS.md](AGENTS.md) for AI-assisted development guidelines
- Check existing tests for usage examples

---

**Built with ❤️ for Privyy.io**

**Status**: ✅ Production Ready | 🔒 Security Audited | 📦 Cross-Compatible
