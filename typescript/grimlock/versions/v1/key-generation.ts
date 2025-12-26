/**
 * V1 Key Generation for Grimlock crypto module
 * 
 * Implements X25519 key pair generation.
 * 
 * Note: This implementation uses Web Crypto API for key generation.
 * For X25519 support, you may need to install @noble/curves package
 * for better cross-platform compatibility.
 */

import type { KeyPair } from '../../types/common';
import { CRYPTO_CONSTANTS_V1 } from './constants';

/**
 * Generate a cryptographically secure random 32-byte array
 */
function getRandomBytes(length: number): Uint8Array {
  if (typeof globalThis !== 'undefined' && (globalThis.crypto?.getRandomValues instanceof Function)) {
    // Browser or modern Node.js environment
    const array = new Uint8Array(length);
    globalThis.crypto.getRandomValues(array);
    return array;
  } else if (typeof require !== 'undefined') {
    // Node.js environment
    const crypto = require('crypto');
    return new Uint8Array(crypto.randomBytes(length));
  } else {
    throw new Error('No secure random number generator available');
  }
}

/**
 * Generate X25519 key pair
 * 
 * This is a simplified implementation. For production use, consider
 * using @noble/curves for better X25519 support across platforms.
 * 
 * Note: This function currently throws an error indicating the need
 * for @noble/curves. Once installed, replace the implementation.
 */
export async function generateKeyPair(): Promise<KeyPair> {
  // Try to use @noble/curves if available
  try {
    // Dynamic import to avoid breaking if package isn't installed
    const { x25519 } = await import('@noble/curves/ed25519.js');
    const privateKey = getRandomBytes(CRYPTO_CONSTANTS_V1.x25519KeySize);
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
  } catch (e) {
    console.log(e);
    // Fallback: throw error with instructions
    throw new Error(
      'X25519 key generation requires @noble/curves package. ' +
      'Please install it: npm install @noble/curves'
    );
  }
}


/**
 * Validate that a key pair is valid
 */
export function validateKeyPair(keyPair: KeyPair): boolean {
  return (
    keyPair.privateKey.length === CRYPTO_CONSTANTS_V1.x25519KeySize &&
    keyPair.publicKey.length === CRYPTO_CONSTANTS_V1.x25519KeySize
  );
}
