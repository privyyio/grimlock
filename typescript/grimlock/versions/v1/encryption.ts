/**
 * V1 Encryption for Grimlock crypto module
 * 
 * Implements AES-256-GCM encryption/decryption for:
 * - Private key encryption/decryption
 * - Message payload encryption/decryption
 * 
 * Uses Web Crypto API for AES-GCM operations.
 */

import type {
  EncryptedPrivateKey,
  MessagePayload,
  EncryptedMessage,
} from '../../types/common';
import { CRYPTO_CONSTANTS_V1 } from './constants';

/**
 * Encrypt private key using AES-256-GCM
 * 
 * @param privateKey - Private key to encrypt (32 bytes)
 * @param encryptionKey - Encryption key (32 bytes)
 * @param aad - Additional authenticated data (optional)
 * @returns Encrypted private key with IV and tag
 */
export async function encryptPrivateKey(
  privateKey: Uint8Array,
  encryptionKey: Uint8Array,
  aad?: Uint8Array
): Promise<EncryptedPrivateKey> {
  if (encryptionKey.length !== CRYPTO_CONSTANTS_V1.aesKeySize) {
    throw new Error(
      `Invalid encryption key size: expected ${CRYPTO_CONSTANTS_V1.aesKeySize}, got ${encryptionKey.length}`
    );
  }

  // Generate random IV
  const iv = getRandomBytes(CRYPTO_CONSTANTS_V1.aesIvSize);

  // Encrypt using AES-GCM
  const { ciphertext, tag } = await aesGcmEncrypt(
    privateKey,
    encryptionKey,
    iv,
    aad
  );

  return {
    ciphertext,
    iv,
    tag,
  };
}

/**
 * Decrypt private key using AES-256-GCM
 * 
 * @param encrypted - Encrypted private key with IV and tag
 * @param encryptionKey - Encryption key (32 bytes)
 * @param aad - Additional authenticated data (optional, must match encryption)
 * @returns Decrypted private key (32 bytes)
 */
export async function decryptPrivateKey(
  encrypted: EncryptedPrivateKey,
  encryptionKey: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  if (encryptionKey.length !== CRYPTO_CONSTANTS_V1.aesKeySize) {
    throw new Error(
      `Invalid encryption key size: expected ${CRYPTO_CONSTANTS_V1.aesKeySize}, got ${encryptionKey.length}`
    );
  }

  if (encrypted.iv.length !== CRYPTO_CONSTANTS_V1.aesIvSize) {
    throw new Error(
      `Invalid IV size: expected ${CRYPTO_CONSTANTS_V1.aesIvSize}, got ${encrypted.iv.length}`
    );
  }

  if (encrypted.tag.length !== CRYPTO_CONSTANTS_V1.aesTagSize) {
    throw new Error(
      `Invalid tag size: expected ${CRYPTO_CONSTANTS_V1.aesTagSize}, got ${encrypted.tag.length}`
    );
  }

  try {
    return await aesGcmDecrypt(
      encrypted.ciphertext,
      encryptionKey,
      encrypted.iv,
      encrypted.tag,
      aad
    );
  } catch (error) {
    throw new Error(
      `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}

/**
 * Encrypt message payload using AES-256-GCM
 * 
 * @param payload - Message payload to encrypt
 * @param encryptionKey - Encryption key (32 bytes)
 * @param iv - Initialization vector (12 bytes)
 * @param aad - Additional authenticated data (optional)
 * @returns Encrypted message with ciphertext and tag
 */
export async function encryptMessagePayload(
  payload: MessagePayload,
  encryptionKey: Uint8Array,
  iv: Uint8Array,
  aad?: Uint8Array
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
  if (encryptionKey.length !== CRYPTO_CONSTANTS_V1.aesKeySize) {
    throw new Error(
      `Invalid encryption key size: expected ${CRYPTO_CONSTANTS_V1.aesKeySize}, got ${encryptionKey.length}`
    );
  }

  if (iv.length !== CRYPTO_CONSTANTS_V1.aesIvSize) {
    throw new Error(
      `Invalid IV size: expected ${CRYPTO_CONSTANTS_V1.aesIvSize}, got ${iv.length}`
    );
  }

  // Serialize payload to JSON
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));

  // Encrypt using AES-GCM
  return await aesGcmEncrypt(plaintext, encryptionKey, iv, aad);
}

/**
 * Decrypt message payload using AES-256-GCM
 * 
 * @param ciphertext - Encrypted ciphertext
 * @param encryptionKey - Encryption key (32 bytes)
 * @param iv - Initialization vector (12 bytes)
 * @param tag - Authentication tag (16 bytes)
 * @param aad - Additional authenticated data (optional, must match encryption)
 * @returns Decrypted message payload
 */
export async function decryptMessagePayload(
  ciphertext: Uint8Array,
  encryptionKey: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array
): Promise<MessagePayload> {
  if (encryptionKey.length !== CRYPTO_CONSTANTS_V1.aesKeySize) {
    throw new Error(
      `Invalid encryption key size: expected ${CRYPTO_CONSTANTS_V1.aesKeySize}, got ${encryptionKey.length}`
    );
  }

  if (iv.length !== CRYPTO_CONSTANTS_V1.aesIvSize) {
    throw new Error(
      `Invalid IV size: expected ${CRYPTO_CONSTANTS_V1.aesIvSize}, got ${iv.length}`
    );
  }

  if (tag.length !== CRYPTO_CONSTANTS_V1.aesTagSize) {
    throw new Error(
      `Invalid tag size: expected ${CRYPTO_CONSTANTS_V1.aesTagSize}, got ${tag.length}`
    );
  }

  try {
    // Decrypt using AES-GCM
    const plaintext = await aesGcmDecrypt(ciphertext, encryptionKey, iv, tag, aad);

    // Deserialize from JSON
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as MessagePayload;

    // Validate payload structure
    if (
      typeof payload.userMessage !== 'string' ||
      typeof payload.assistantResponse !== 'string'
    ) {
      throw new Error('Invalid payload structure');
    }

    return payload;
  } catch (error) {
    throw new Error(
      `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}

/**
 * AES-GCM encryption using Web Crypto API
 */
async function aesGcmEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad?: Uint8Array
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
  // Use Web Crypto API (available in browser and Next.js)
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    // Use type assertion to satisfy TypeScript's strict BufferSource typing
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw',
      key as unknown as ArrayBuffer,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const encrypted = await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv as unknown as ArrayBuffer,
        additionalData: aad ? (aad as unknown as ArrayBuffer) : undefined,
        tagLength: CRYPTO_CONSTANTS_V1.aesTagSize * 8, // in bits
      },
      cryptoKey,
      plaintext as unknown as ArrayBuffer
    );

    const encryptedArray = new Uint8Array(encrypted);
    // In Web Crypto API, tag is appended to ciphertext
    const tag = encryptedArray.slice(-CRYPTO_CONSTANTS_V1.aesTagSize);
    const ciphertext = encryptedArray.slice(0, -CRYPTO_CONSTANTS_V1.aesTagSize);

    return { ciphertext, tag };
  } else {
    throw new Error('Web Crypto API is required but not available');
  }
}

/**
 * AES-GCM decryption using Web Crypto API
 */
async function aesGcmDecrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  // Use Web Crypto API (available in browser and Next.js)
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    // Use type assertion to satisfy TypeScript's strict BufferSource typing
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw',
      key as unknown as ArrayBuffer,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // In Web Crypto API, tag is appended to ciphertext
    const encrypted = new Uint8Array(ciphertext.length + tag.length);
    encrypted.set(ciphertext);
    encrypted.set(tag, ciphertext.length);

    const plaintext = await globalThis.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv as unknown as ArrayBuffer,
        additionalData: aad ? (aad as unknown as ArrayBuffer) : undefined,
        tagLength: CRYPTO_CONSTANTS_V1.aesTagSize * 8, // in bits
      },
      cryptoKey,
      encrypted as unknown as ArrayBuffer
    );

    return new Uint8Array(plaintext);
  } else {
    throw new Error('Web Crypto API is required but not available');
  }
}

/**
 * Generate random bytes
 */
function getRandomBytes(length: number): Uint8Array {
  // Use Web Crypto API (available in browser and Next.js)
  if (typeof globalThis !== 'undefined' && (globalThis.crypto?.getRandomValues instanceof Function)) {
    const array = new Uint8Array(length);
    globalThis.crypto.getRandomValues(array);
    return array;
  } else {
    throw new Error('Web Crypto API is required but not available');
  }
}
