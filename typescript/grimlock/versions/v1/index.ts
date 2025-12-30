/**
 * V1 API Implementation for Grimlock crypto module
 * 
 * This is the complete v1 API that follows the protocol specification.
 * All operations use the v1 constants and algorithms.
 */

import type { GrimLock, GrimlockV1 } from '../../types/v1';
import type {
  KeyPair,
  SerializedKeyPair,
  KdfParams,
  EncryptedPrivateKey,
  MessagePayload,
  MessageContext,
  EncryptedMessage,
  RecoveryKey,
} from '../../types/common';

// Import implementations
import { generateKeyPair as generateKeyPairImpl } from './key-generation';
import {
  derivePasscodeKey as derivePasscodeKeyImpl,
  deriveRecoveryKey as deriveRecoveryKeyImpl,
  deriveMessageKey as deriveMessageKeyImpl,
} from './key-derivation';
import {
  encryptPrivateKey as encryptPrivateKeyImpl,
  decryptPrivateKey as decryptPrivateKeyImpl,
  encryptMessagePayload as encryptMessagePayloadImpl,
  decryptMessagePayload as decryptMessagePayloadImpl,
} from './encryption';
import { computeSharedSecret } from './ecdh';
import {
  generateRecoveryKey as generateRecoveryKeyImpl,
} from './recovery-key';
import { serializeKeyPair, deserializeKeyPair } from '../../utils/serialization';
import { CRYPTO_CONSTANTS_V1 } from './constants';
// Helper function for generating random bytes
function getRandomBytesForEncryption(length: number): Uint8Array {
  // Use Web Crypto API (available in browser and Next.js)
  if (typeof globalThis !== 'undefined' && (globalThis.crypto?.getRandomValues instanceof Function)) {
    const array = new Uint8Array(length);
    globalThis.crypto.getRandomValues(array);
    return array;
  } else {
    throw new Error('Web Crypto API is required but not available');
  }
}

/**
 * V1 API implementation
 */
export const v1: GrimlockV1 = {
  // Key Generation
  generateKeyPair: generateKeyPairImpl,

  // Key Derivation
  derivePasscodeKey: derivePasscodeKeyImpl,
  deriveRecoveryKey: deriveRecoveryKeyImpl,

  // Private Key Operations
  encryptPrivateKey: encryptPrivateKeyImpl,
  decryptPrivateKey: decryptPrivateKeyImpl,

  // Message Operations
  encryptMessage: async (
    payload: MessagePayload,
    userPublicKey: Uint8Array,
    context: MessageContext
  ): Promise<EncryptedMessage> => {
    // Step 1: Generate ephemeral key pair
    const ephemeralKeyPair = await generateKeyPairImpl();

    // Step 2: Compute shared secret using ECDH
    const sharedSecret = await computeSharedSecret(
      ephemeralKeyPair.privateKey,
      userPublicKey
    );

    // Step 3: Derive message key from shared secret (match Go format)
    const contextString = `${context.conversationId}||${context.messageId}`;
    const messageKey = await deriveMessageKeyImpl(sharedSecret, contextString);

    // Step 4: Generate random IV
    const iv = getRandomBytesForEncryption(CRYPTO_CONSTANTS_V1.aesIvSize);

    // Step 5: Create metadata as AAD (additional authenticated data)
    const metadata = new TextEncoder().encode(`${context.conversationId}||${context.messageId}`);

    // Step 6: Encrypt payload with AAD
    const { ciphertext, tag } = await encryptMessagePayloadImpl(
      payload,
      messageKey,
      iv,
      metadata
    );

    // Step 7: Securely erase ephemeral private key and derived keys
    // (In JavaScript, we can't guarantee complete erasure, but we try)
    ephemeralKeyPair.privateKey.fill(0);
    sharedSecret.fill(0);
    messageKey.fill(0);

    return {
      ephemeralPublicKey: ephemeralKeyPair.publicKey,
      iv,
      tag,
      ciphertext,
    };
  },

  decryptMessage: async (
    encrypted: EncryptedMessage,
    userPrivateKey: Uint8Array,
    context: MessageContext,
    metadata?: Uint8Array
  ): Promise<MessagePayload> => {
    // Step 1: Compute shared secret using ECDH
    const sharedSecret = await computeSharedSecret(
      userPrivateKey,
      encrypted.ephemeralPublicKey
    );

    // Step 2: Derive message key from shared secret (match Go format)
    const contextString = `${context.conversationId}||${context.messageId}`;
    const messageKey = await deriveMessageKeyImpl(sharedSecret, contextString);

    // Step 3: Create metadata as AAD if not provided
    const aad = metadata || new TextEncoder().encode(contextString);

    // Step 4: Decrypt payload with AAD
    const payload = await decryptMessagePayloadImpl(
      encrypted.ciphertext,
      messageKey,
      encrypted.iv,
      encrypted.tag,
      aad
    );

    // Step 5: Securely erase derived keys
    sharedSecret.fill(0);
    messageKey.fill(0);

    return payload;
  },

  // Recovery Key
  generateRecoveryKey: generateRecoveryKeyImpl,

  // Utilities
  serializeKeyPair,
  deserializeKeyPair,

  // Constants
  constants: CRYPTO_CONSTANTS_V1,

  // Version info
  version: 'v1',
};
