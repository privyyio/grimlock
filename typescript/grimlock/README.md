# Grimlock Crypto Module

Versioned cryptographic operations module for privyy.io.

## Overview

Grimlock provides a versioned API for cryptographic operations including:
- X25519 key pair generation and ECDH
- Argon2id key derivation from passcodes
- AES-256-GCM encryption/decryption
- HKDF-SHA512 for key derivation
- Recovery key generation and management

## Installation

The module requires the following optional dependencies for full functionality:

```bash
# For X25519 operations
npm install @noble/curves

# For Argon2id (Node.js)
npm install argon2

# For Argon2id (Browser)
npm install argon2-browser

# For BIP39 mnemonic support (optional)
npm install bip39
```

**Note**: The module will work without these dependencies but will throw helpful error messages when operations requiring them are called.

## Usage

### Default Export (Latest Version)

```typescript
import grimlock from '@privyyio/grimlock';

// Generate key pair
const keyPair = await grimlock.generateKeyPair();

// Derive passcode key
const passcodeKey = await grimlock.derivePasscodeKey('123456', {
  salt: new Uint8Array(32),
  argon2Params: {
    timeCost: 4,
    memoryCost: 128 * 1024,
    parallelism: 2,
  },
});

// Encrypt private key
const encrypted = await grimlock.encryptPrivateKey(
  keyPair.privateKey,
  passcodeKey
);
```

### Explicit Version Selection

```typescript
import { v1, v2 } from '@privyyio/grimlock';

// Use v1 explicitly
const keyPair = await v1.generateKeyPair();

// Use v2 (when implemented)
// const keyPair = await v2.generateKeyPair();
```

### Version Manager

```typescript
import { getVersionManager } from '@privyyio/grimlock';

const manager = getVersionManager();
const latest = manager.getLatestVersion(); // "v1"
const v1Metadata = manager.getVersion('v1');
```

### Version Detection

```typescript
import { detectVersion, getVersionForData, requiresMigration } from '@privyyio/grimlock';

const encrypted = await fetchEncryptedMessage(messageId);
const version = detectVersion(encrypted) || 'v1';

// Get appropriate API version
const crypto = getVersionForData(encrypted);
const decrypted = await crypto.decryptMessage(encrypted, privateKey, context);

// Check if migration is needed
const needsMigration = requiresMigration(encrypted, 'v2');
```

## API Reference

### Key Generation

- `generateKeyPair(): Promise<KeyPair>` - Generate X25519 key pair

### Key Derivation

- `derivePasscodeKey(passcode: string, params: KdfParams): Promise<Uint8Array>` - Derive key from passcode using Argon2id
- `deriveRecoveryKey(recoveryKeyBytes: Uint8Array): Promise<Uint8Array>` - Derive key from recovery key using HKDF-SHA512

### Private Key Operations

- `encryptPrivateKey(privateKey: Uint8Array, encryptionKey: Uint8Array, aad?: Uint8Array): Promise<EncryptedPrivateKey>` - Encrypt private key
- `decryptPrivateKey(encrypted: EncryptedPrivateKey, encryptionKey: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>` - Decrypt private key

### Message Operations

- `encryptMessage(payload: MessagePayload, userPublicKey: Uint8Array, context: MessageContext): Promise<EncryptedMessage>` - Encrypt message payload
- `decryptMessage(encrypted: EncryptedMessage, userPrivateKey: Uint8Array, context: MessageContext, metadata?: Uint8Array): Promise<MessagePayload>` - Decrypt message payload

### Recovery Key

- `generateRecoveryKey(): RecoveryKey` - Generate recovery key

### Utilities

- `serializeKeyPair(keyPair: KeyPair): SerializedKeyPair` - Serialize key pair to Base64
- `deserializeKeyPair(serialized: SerializedKeyPair): KeyPair` - Deserialize key pair from Base64

### Version Utilities

- `detectVersion(data: unknown): string | null` - Detect version from encrypted data structure
- `getVersionForData(data: unknown): GrimLock` - Get the appropriate API version for decrypting data
- `requiresMigration(data: unknown, targetVersion: string): boolean` - Check if data needs migration to a newer version

## Constants

All constants use "grimlock" prefix:

- `grimlock-encryption-salt` - HKDF salt for message encryption
- `grimlock-recovery-salt` - HKDF salt for recovery key derivation
- `grimlock-message-key` - HKDF info for message key derivation
- `grimlock-recovery-key-derivation` - HKDF info for recovery key derivation
- `grimlock-dual-encryption` - HKDF info for dual encryption
- `grimlock-default-pepper` - Default pepper for passcode HMAC

## Versioning

The module uses namespace-based versioning:
- `v1` - Current stable version
- `v2` - Future version (placeholder)

Each version maintains backward compatibility for decryption operations while allowing new algorithms for encryption.

## Security Notes

1. **Memory Security**: The module attempts to zero out sensitive data, but JavaScript's garbage collection makes complete memory erasure difficult.

2. **Random Number Generation**: Uses platform-native secure random number generators (Web Crypto API in browser, Node.js crypto in server).

3. **Key Management**: Private keys should never be logged or stored in plaintext. Always use encrypted storage.

4. **Dependencies**: Ensure all cryptographic dependencies are kept up to date for security patches.

## Platform Support

- **Browser**: Uses Web Crypto API for AES-GCM, HMAC, HKDF
- **Node.js**: Uses Node.js crypto module for AES-GCM, HMAC, HKDF
- **X25519**: Requires @noble/curves (works in both environments)
- **Argon2id**: Requires argon2 (Node.js) or argon2-browser (browser)

## License

Part of privyy.io project.
