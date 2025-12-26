/**
 * Version metadata types for Grimlock crypto module
 */

import type { Argon2Params } from './common';

/**
 * Cryptographic constants for a version
 */
export interface CryptoConstants {
  // X25519
  x25519KeySize: number; // 32

  // Argon2id
  argon2TimeCost: number;
  argon2MemoryCost: number;
  argon2Parallelism: number;
  argon2SaltSize: number; // 32

  // AES-GCM
  aesKeySize: number; // 32 (256 bits)
  aesIvSize: number; // 12 (96 bits)
  aesTagSize: number; // 16 (128 bits)

  // HKDF
  hkdfSaltEncryption: string; // 'grimlock-encryption-salt'
  hkdfSaltRecovery: string; // 'grimlock-recovery-salt'
  hkdfInfoMessage: string; // 'grimlock-message-key'
  hkdfInfoRecovery: string; // 'grimlock-recovery-key-derivation'
  hkdfInfoDualEncryption: string; // 'grimlock-dual-encryption'
  hkdfOutputLength: number; // 32

  // Recovery Key
  recoveryKeySize: number; // 32 (256 bits)

  // Default pepper
  defaultPepper: string; // 'grimlock-default-pepper'
}

/**
 * Algorithm specifications for a version
 */
export interface AlgorithmSpec {
  keyExchange: string; // "X25519"
  keyDerivation: string; // "Argon2id-v1"
  encryption: string; // "AES-256-GCM"
  hkdf: string; // "HKDF-SHA512"
}

/**
 * Version metadata
 */
export interface VersionMetadata {
  version: string; // "v1", "v2", etc.
  algorithms: AlgorithmSpec;
  constants: CryptoConstants;
  deprecated?: boolean;
  migrationGuide?: string;
}
