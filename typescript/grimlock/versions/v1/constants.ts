/**
 * V1 Cryptographic Constants for Grimlock crypto module
 * 
 * All constant strings use "grimlock" prefix instead of "okara"
 */

import type { CryptoConstants } from '../../types/version';

/**
 * V1 cryptographic constants
 */
export const CRYPTO_CONSTANTS_V1: CryptoConstants = {
  // X25519
  x25519KeySize: 32,

  // Argon2id
  argon2TimeCost: 4,
  argon2MemoryCost: 128 * 1024, // 128MB in KB
  argon2Parallelism: 2,
  argon2SaltSize: 32,

  // AES-GCM
  aesKeySize: 32, // 256 bits
  aesIvSize: 12, // 96 bits (AES-GCM standard)
  aesTagSize: 16, // 128 bits

  // HKDF
  hkdfSaltEncryption: 'grimlock-encryption-salt',
  hkdfSaltRecovery: 'grimlock-recovery-salt',
  hkdfInfoMessage: 'grimlock-message-key',
  hkdfInfoRecovery: 'grimlock-recovery-key-derivation',
  hkdfInfoDualEncryption: 'grimlock-dual-encryption',
  hkdfOutputLength: 32,

  // Recovery Key
  recoveryKeySize: 32, // 256 bits

  // Default pepper
  defaultPepper: 'grimlock-default-pepper',
} as const;
