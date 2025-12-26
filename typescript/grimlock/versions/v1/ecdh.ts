/**
 * V1 ECDH (Elliptic Curve Diffie-Hellman) for Grimlock crypto module
 * 
 * Implements X25519 ECDH for shared secret computation.
 * 
 * Note: This implementation requires @noble/curves for X25519 support.
 */

import { CRYPTO_CONSTANTS_V1 } from './constants';

/**
 * Compute shared secret using X25519 ECDH
 * 
 * @param privateKey - Our private key (32 bytes)
 * @param publicKey - Their public key (32 bytes)
 * @returns Shared secret (32 bytes)
 */
export async function computeSharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Promise<Uint8Array> {
  // Validate key sizes
  if (privateKey.length !== CRYPTO_CONSTANTS_V1.x25519KeySize) {
    throw new Error(
      `Invalid private key size: expected ${CRYPTO_CONSTANTS_V1.x25519KeySize}, got ${privateKey.length}`
    );
  }

  if (publicKey.length !== CRYPTO_CONSTANTS_V1.x25519KeySize) {
    throw new Error(
      `Invalid public key size: expected ${CRYPTO_CONSTANTS_V1.x25519KeySize}, got ${publicKey.length}`
    );
  }

  // Try to use @noble/curves if available
  try {
    const { x25519 } = await import('@noble/curves/ed25519.js');
    return x25519.getSharedSecret(privateKey, publicKey);
  } catch {
    // Fallback: throw error with instructions
    throw new Error(
      'X25519 ECDH requires @noble/curves package. ' +
      'Please install it: npm install @noble/curves'
    );
  }
}
