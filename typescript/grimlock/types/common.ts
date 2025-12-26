/**
 * Common types shared across all Grimlock crypto module versions
 */

/**
 * Key pair structure (32 bytes each for X25519)
 */
export interface KeyPair {
  privateKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array; // 32 bytes
}

/**
 * Serialized key pair for storage/transmission
 */
export interface SerializedKeyPair {
  privateKey: string; // Base64 encoded
  publicKey: string; // Base64 encoded
}

/**
 * KDF (Key Derivation Function) parameters for Argon2id
 */
export interface Argon2Params {
  timeCost: number; // 4 (iterations)
  memoryCost: number; // 128 * 1024 (128MB in KB)
  parallelism: number; // 2
}

/**
 * Complete KDF parameters including salt
 */
export interface KdfParams {
  salt: Uint8Array; // 32 bytes (256-bit)
  argon2Params: Argon2Params;
  serverPepper?: string; // Optional server-side pepper for HMAC
}

/**
 * Encrypted private key structure
 */
export interface EncryptedPrivateKey {
  ciphertext: Uint8Array;
  iv: Uint8Array; // 12 bytes (AES-GCM nonce)
  tag: Uint8Array; // 16 bytes (AES-GCM auth tag)
}

/**
 * Message payload to be encrypted
 */
export interface MessagePayload {
  userMessage: string;
  assistantResponse: string;
  context?: Record<string, unknown>;
}

/**
 * Context for message encryption/decryption
 */
export interface MessageContext {
  conversationId: string;
  messageId: string;
}

/**
 * Encrypted message structure
 */
export interface EncryptedMessage {
  ephemeralPublicKey: Uint8Array; // 32 bytes (X25519)
  iv: Uint8Array; // 12 bytes
  tag: Uint8Array; // 16 bytes
  ciphertext: Uint8Array;
}

/**
 * Recovery key structure
 */
export interface RecoveryKey {
  raw: Uint8Array; // 32 bytes
  base64: string; // Base64 encoded (44 characters)
  mnemonic?: string; // Optional BIP39 mnemonic (24 words)
}
