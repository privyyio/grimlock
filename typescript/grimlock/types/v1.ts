/**
 * V1-specific type definitions for Grimlock crypto module
 */

import type {
  KeyPair,
  SerializedKeyPair,
  KdfParams,
  EncryptedPrivateKey,
  MessagePayload,
  MessageContext,
  EncryptedMessage,
  RecoveryKey,
} from './common';

/**
 * V1 key pair with version tag
 */
export interface KeyPairV1 extends KeyPair {
  _version: 'v1';
}

/**
 * V1 encrypted message with version tag
 */
export interface EncryptedMessageV1 extends EncryptedMessage {
  _version: 'v1';
}

/**
 * V1 encrypted private key with version tag
 */
export interface EncryptedPrivateKeyV1 extends EncryptedPrivateKey {
  _version: 'v1';
}

/**
 * Base GrimLock interface with common API methods
 */
export interface GrimLock {
  // Key Generation
  generateKeyPair: () => Promise<KeyPair>;

  // Key Derivation
  derivePasscodeKey: (
    passcode: string,
    params: KdfParams
  ) => Promise<Uint8Array>;
  deriveRecoveryKey: (recoveryKeyBytes: Uint8Array) => Promise<Uint8Array>;

  // Private Key Operations
  encryptPrivateKey: (
    privateKey: Uint8Array,
    encryptionKey: Uint8Array,
    aad?: Uint8Array
  ) => Promise<EncryptedPrivateKey>;
  decryptPrivateKey: (
    encrypted: EncryptedPrivateKey,
    encryptionKey: Uint8Array,
    aad?: Uint8Array
  ) => Promise<Uint8Array>;

  // Message Operations
  encryptMessage: (
    payload: MessagePayload,
    userPublicKey: Uint8Array,
    context: MessageContext
  ) => Promise<EncryptedMessage>;
  decryptMessage: (
    encrypted: EncryptedMessage,
    userPrivateKey: Uint8Array,
    context: MessageContext,
    metadata?: Uint8Array
  ) => Promise<MessagePayload>;

  // Recovery Key
  generateRecoveryKey: () => RecoveryKey;

  // Utilities
  serializeKeyPair: (keyPair: KeyPair) => SerializedKeyPair;
  deserializeKeyPair: (serialized: SerializedKeyPair) => KeyPair;

  // Constants
  constants: import('./version').CryptoConstants;

  // Version info
  version: string;
}

/**
 * V1 API interface
 */
export interface GrimlockV1 extends GrimLock {
  // Version info
  version: 'v1';
}
