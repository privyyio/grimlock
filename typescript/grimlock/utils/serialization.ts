/**
 * Serialization utilities for Grimlock crypto module
 * 
 * Provides functions to serialize/deserialize key pairs and other
 * cryptographic data structures for storage and transmission.
 */

import type { KeyPair, SerializedKeyPair } from '../types/common';
import { base64Encode, base64Decode } from './encoding';

/**
 * Serialize key pair to Base64 strings
 */
export function serializeKeyPair(keyPair: KeyPair): SerializedKeyPair {
  return {
    privateKey: base64Encode(keyPair.privateKey),
    publicKey: base64Encode(keyPair.publicKey),
  };
}

/**
 * Deserialize key pair from Base64 strings
 */
export function deserializeKeyPair(serialized: SerializedKeyPair): KeyPair {
  return {
    privateKey: base64Decode(serialized.privateKey),
    publicKey: base64Decode(serialized.publicKey),
  };
}

/**
 * Serialize encrypted private key to Base64 strings
 */
export function serializeEncryptedPrivateKey(
  encrypted: {
    ciphertext: Uint8Array;
    iv: Uint8Array;
    tag: Uint8Array;
  }
): {
  ciphertext: string;
  iv: string;
  tag: string;
} {
  return {
    ciphertext: base64Encode(encrypted.ciphertext),
    iv: base64Encode(encrypted.iv),
    tag: base64Encode(encrypted.tag),
  };
}

/**
 * Deserialize encrypted private key from Base64 strings
 */
export function deserializeEncryptedPrivateKey(serialized: {
  ciphertext: string;
  iv: string;
  tag: string;
}): {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
} {
  return {
    ciphertext: base64Decode(serialized.ciphertext),
    iv: base64Decode(serialized.iv),
    tag: base64Decode(serialized.tag),
  };
}

/**
 * Serialize encrypted message to Base64 strings
 */
export function serializeEncryptedMessage(
  encrypted: {
    ephemeralPublicKey: Uint8Array;
    iv: Uint8Array;
    tag: Uint8Array;
    ciphertext: Uint8Array;
  }
): {
  ephemeralPublicKey: string;
  iv: string;
  tag: string;
  ciphertext: string;
} {
  return {
    ephemeralPublicKey: base64Encode(encrypted.ephemeralPublicKey),
    iv: base64Encode(encrypted.iv),
    tag: base64Encode(encrypted.tag),
    ciphertext: base64Encode(encrypted.ciphertext),
  };
}

/**
 * Deserialize encrypted message from Base64 strings
 */
export function deserializeEncryptedMessage(serialized: {
  ephemeralPublicKey: string;
  iv: string;
  tag: string;
  ciphertext: string;
}): {
  ephemeralPublicKey: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
  ciphertext: Uint8Array;
} {
  return {
    ephemeralPublicKey: base64Decode(serialized.ephemeralPublicKey),
    iv: base64Decode(serialized.iv),
    tag: base64Decode(serialized.tag),
    ciphertext: base64Decode(serialized.ciphertext),
  };
}
