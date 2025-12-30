/**
 * V1 Recovery Key Operations for Grimlock crypto module
 * 
 * Implements recovery key generation and encoding.
 */

import type { RecoveryKey } from '../../types/common';
import { CRYPTO_CONSTANTS_V1 } from './constants';
import { base64Encode, base64Decode } from '../../utils/encoding';

/**
 * Generate a cryptographically secure random 32-byte array
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

/**
 * Generate a recovery key
 * 
 * Generates a 256-bit (32-byte) cryptographically secure random key
 * and encodes it in multiple formats for user convenience.
 * 
 * @returns Recovery key with raw bytes, Base64, and optional mnemonic
 */
export function generateRecoveryKey(): RecoveryKey {
  // Generate 32 random bytes (256 bits)
  const raw = getRandomBytes(CRYPTO_CONSTANTS_V1.recoveryKeySize);

  // Encode as Base64 (44 characters)
  const base64 = base64Encode(raw);

  // Optional: Generate BIP39 mnemonic (requires bip39 package)
  // For now, we'll leave it undefined. Users can install bip39
  // and generate mnemonic separately if needed.
  const mnemonic = undefined; // TODO: Add BIP39 support if needed

  return {
    raw,
    base64,
    mnemonic,
  };
}

/**
 * Parse recovery key from Base64 string
 * 
 * @param base64Key - Base64 encoded recovery key
 * @returns Recovery key with raw bytes
 */
export function parseRecoveryKeyFromBase64(base64Key: string): RecoveryKey {
  const raw = base64Decode(base64Key);

  if (raw.length !== CRYPTO_CONSTANTS_V1.recoveryKeySize) {
    throw new Error(
      `Invalid recovery key size: expected ${CRYPTO_CONSTANTS_V1.recoveryKeySize} bytes, got ${raw.length}`
    );
  }

  return {
    raw,
    base64: base64Key,
    mnemonic: undefined,
  };
}

/**
 * Parse recovery key from BIP39 mnemonic
 * 
 * This requires the bip39 package to be installed.
 * 
 * @param mnemonic - BIP39 mnemonic phrase (24 words)
 * @returns Recovery key with raw bytes
 */
export function parseRecoveryKeyFromMnemonic(mnemonic: string): RecoveryKey {
  // This is a placeholder - requires bip39 package
  // 
  // Example implementation:
  // const bip39 = require('bip39');
  // const entropy = bip39.mnemonicToEntropy(mnemonic);
  // const raw = hexDecode(entropy);
  //
  // if (raw.length !== CRYPTO_CONSTANTS_V1.recoveryKeySize) {
  //   throw new Error('Invalid mnemonic entropy length');
  // }
  //
  // return {
  //   raw,
  //   base64: base64Encode(raw),
  //   mnemonic,
  // };
  
  throw new Error(
    'BIP39 mnemonic parsing requires bip39 package. ' +
    'Please install it: npm install bip39'
  );
}
