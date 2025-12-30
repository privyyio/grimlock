/**
 * V1 Key Derivation for Grimlock crypto module
 * 
 * Implements:
 * - Argon2id for passcode key derivation
 * - HKDF-SHA512 for shared secret and recovery key derivation
 * 
 * Note: Argon2id requires argon2 package (Node.js) or argon2-browser (browser).
 * HKDF uses Web Crypto API where available.
 */

import type { KdfParams } from '../../types/common';
import { CRYPTO_CONSTANTS_V1 } from './constants';

/**
 * Derive encryption key from passcode using Argon2id
 * 
 * Process:
 * 1. Argon2id(passcode, salt, params) - derive key directly
 * 
 * Note: Aligned with Go implementation for cross-compatibility.
 * Previously used HMAC-SHA256 preprocessing, but removed to match Go.
 * 
 * @param passcode - User's passcode (string)
 * @param params - KDF parameters including salt and Argon2 params
 * @returns Derived encryption key (32 bytes)
 */
export async function derivePasscodeKey(
  passcode: string,
  params: KdfParams
): Promise<Uint8Array> {
  // Derive key using Argon2id directly (matching Go implementation)
  const derivedKey = await argon2id(
    new TextEncoder().encode(passcode),  // Use passcode directly, no HMAC preprocessing
    params.salt,
    params.argon2Params.timeCost,
    params.argon2Params.memoryCost,
    params.argon2Params.parallelism
  );

  return derivedKey;
}

/**
 * Derive encryption key from recovery key using HKDF-SHA512
 * 
 * @param recoveryKeyBytes - Raw recovery key bytes (32 bytes)
 * @returns Derived encryption key (32 bytes)
 */
export async function deriveRecoveryKey(
  recoveryKeyBytes: Uint8Array
): Promise<Uint8Array> {
  if (recoveryKeyBytes.length !== CRYPTO_CONSTANTS_V1.recoveryKeySize) {
    throw new Error(
      `Invalid recovery key size: expected ${CRYPTO_CONSTANTS_V1.recoveryKeySize}, got ${recoveryKeyBytes.length}`
    );
  }

  return hkdfSha512(
    recoveryKeyBytes,
    new TextEncoder().encode(CRYPTO_CONSTANTS_V1.hkdfSaltRecovery),
    new TextEncoder().encode(CRYPTO_CONSTANTS_V1.hkdfInfoRecovery),
    CRYPTO_CONSTANTS_V1.hkdfOutputLength
  );
}

/**
 * Derive message encryption key from shared secret using HKDF-SHA512
 * 
 * Note: Context should be in format "conv-123||msg-456" to match Go implementation.
 * 
 * @param sharedSecret - ECDH shared secret (32 bytes)
 * @param context - Context string (conversationId||messageId)
 * @returns Derived message key (32 bytes)
 */
export async function deriveMessageKey(
  sharedSecret: Uint8Array,
  context: string
): Promise<Uint8Array> {
  // Match Go format: "grimlock-message-keyconv-123||msg-456"
  const info = `${CRYPTO_CONSTANTS_V1.hkdfInfoMessage}${context}`;
  return hkdfSha512(
    sharedSecret,
    new TextEncoder().encode(CRYPTO_CONSTANTS_V1.hkdfSaltEncryption),
    new TextEncoder().encode(info),
    CRYPTO_CONSTANTS_V1.hkdfOutputLength
  );
}

/**
 * HMAC-SHA256 implementation
 */
async function hmacSha256(
  data: Uint8Array,
  key: Uint8Array
): Promise<Uint8Array> {
  // Use Web Crypto API (available in browser and Next.js)
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    // Use type assertion to satisfy TypeScript's strict BufferSource typing
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw',
      key as unknown as ArrayBuffer,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await globalThis.crypto.subtle.sign(
      'HMAC',
      cryptoKey,
      data as unknown as ArrayBuffer
    );
    return new Uint8Array(signature);
  } else {
    throw new Error('Web Crypto API is required but not available');
  }
}

/**
 * HKDF-SHA512 implementation (RFC 5869)
 * 
 * @param ikm - Input key material
 * @param salt - Salt
 * @param info - Info/context
 * @param length - Output length in bytes
 */
async function hkdfSha512(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  // Extract phase: HMAC-SHA512(salt, IKM) - per RFC 5869
  // hmacSha512(data, key) so we pass (ikm, salt) to get HMAC(key=salt, data=ikm)
  const prk = await hmacSha512(ikm, salt);

  // Expand phase
  const n = Math.ceil(length / 64); // SHA-512 output is 64 bytes
  const okm = new Uint8Array(n * 64);

  let previous: Uint8Array = new Uint8Array(0);
  for (let i = 0; i < n; i++) {
    const t = new Uint8Array(previous.length + info.length + 1);
    t.set(previous);
    t.set(info, previous.length);
    t[previous.length + info.length] = i + 1;

    previous = (await hmacSha512(t, prk)) as Uint8Array;  // HMAC(key=prk, data=t)
    okm.set(previous, i * 64);
  }

  return okm.slice(0, length);
}

/**
 * HMAC-SHA512 implementation
 */
async function hmacSha512(
  data: Uint8Array,
  key: Uint8Array
): Promise<Uint8Array> {
  // Use Web Crypto API (available in browser and Next.js)
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    // Use type assertion to satisfy TypeScript's strict BufferSource typing
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw',
      key as unknown as ArrayBuffer,
      { name: 'HMAC', hash: 'SHA-512' },
      false,
      ['sign']
    );

    const signature = await globalThis.crypto.subtle.sign(
      'HMAC',
      cryptoKey,
      data as unknown as ArrayBuffer
    );
    return new Uint8Array(signature);
  } else {
    throw new Error('Web Crypto API is required but not available');
  }
}

/**
 * Argon2id key derivation
 * 
 * @param password - Password bytes
 * @param salt - Salt bytes
 * @param timeCost - Time cost (iterations)
 * @param memoryCost - Memory cost (in KB)
 * @param parallelism - Parallelism factor
 * @returns Derived key (32 bytes)
 */
async function argon2id(
  password: Uint8Array,
  salt: Uint8Array,
  timeCost: number,
  memoryCost: number,
  parallelism: number
): Promise<Uint8Array> {
  // Use argon2-browser for both browser and Next.js (works in both environments)
  try {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore - argon2-browser types may not be available
    const argon2Module = await import('argon2-browser');
    // argon2-browser exports everything under default
    const argon2 = argon2Module.default;
    const result = await argon2.hash({
      pass: password,
      salt: salt,
      time: timeCost,
      mem: memoryCost,
      parallelism: parallelism,
      hashLen: 32,
      type: argon2.ArgonType?.Argon2id || 2, // Argon2id type
    });
    return new Uint8Array(result.hash);
  } catch (error) {
    // Fallback: throw error with instructions
    throw new Error(
      'Argon2id requires argon2-browser package. ' +
      'Please install it: npm install argon2-browser. ' +
      `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}
