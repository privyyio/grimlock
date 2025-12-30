/**
 * Grimlock Crypto Module Test Suite
 * 
 * Comprehensive tests for all grimlock functionality including:
 * - Key generation
 * - Passcode-based encryption
 * - Message encryption/decryption
 * - Recovery keys
 * - Version management
 * - Serialization
 * - ECDH operations
 */

import grimlock, { v1, getVersionManager, detectVersion, requiresMigration, getVersionForData } from './index';
import type { MessagePayload, MessageContext, KdfParams } from './types/common';

// ANSI color codes for pretty output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

let testsPassed = 0;
let testsFailed = 0;

/**
 * Simple test assertion helper
 */
function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

/**
 * Test runner helper
 */
async function runTest(testName: string, testFn: () => Promise<void>): Promise<void> {
  try {
    console.log(`${colors.cyan}▶${colors.reset} Running: ${testName}`);
    await testFn();
    console.log(`${colors.green}✓${colors.reset} ${testName}\n`);
    testsPassed++;
  } catch (error) {
    console.error(`${colors.red}✗${colors.reset} ${testName}`);
    console.error(`${colors.red}Error:${colors.reset}`, error instanceof Error ? error.message : error);
    console.error('');
    testsFailed++;
  }
}

/**
 * Helper to compare Uint8Arrays
 */
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Helper to generate KDF parameters
 */
function generateKdfParams(): KdfParams {
  const salt = new Uint8Array(32);
  if (typeof globalThis !== 'undefined' && (globalThis.crypto?.getRandomValues instanceof Function)) {
    globalThis.crypto.getRandomValues(salt);
  } else {
    // For Node.js environments
    const crypto = require('crypto');
    const randomBytes = crypto.randomBytes(32);
    salt.set(randomBytes);
  }

  return {
    salt,
    argon2Params: {
      timeCost: 4,
      memoryCost: 128 * 1024, // 128MB in KB
      parallelism: 2,
    },
  };
}

// =============================================================================
// TEST SUITE
// =============================================================================

/**
 * Test 1: Basic key pair generation
 */
async function testGenerateKeyPair(): Promise<void> {
  const keyPair = await grimlock.generateKeyPair();

  assert(keyPair.privateKey instanceof Uint8Array, 'Private key should be Uint8Array');
  assert(keyPair.publicKey instanceof Uint8Array, 'Public key should be Uint8Array');
  assert(keyPair.privateKey.length === 32, 'Private key should be 32 bytes');
  assert(keyPair.publicKey.length === 32, 'Public key should be 32 bytes');

  // Generate another key pair to ensure uniqueness
  const keyPair2 = await grimlock.generateKeyPair();
  assert(!arraysEqual(keyPair.privateKey, keyPair2.privateKey), 'Key pairs should be unique');
  assert(!arraysEqual(keyPair.publicKey, keyPair2.publicKey), 'Public keys should be unique');
}

/**
 * Test 2: Passcode-based private key encryption and decryption
 */
async function testPasscodeBasedEncryption(): Promise<void> {
  // Generate user key pair
  const keyPair = await grimlock.generateKeyPair();

  // Generate KDF parameters
  const kdfParams = generateKdfParams();

  // User enters passcode
  const passcode = 'my-secure-passcode-123';

  // Derive encryption key from passcode
  const passcodeKey = await grimlock.derivePasscodeKey(passcode, kdfParams);
  assert(passcodeKey.length === 32, 'Passcode key should be 32 bytes');

  // Encrypt private key
  const userIdBytes = new TextEncoder().encode('user-123');
  const encrypted = await grimlock.encryptPrivateKey(
    keyPair.privateKey,
    passcodeKey,
    userIdBytes
  );

  assert(encrypted.ciphertext.length > 0, 'Ciphertext should not be empty');
  assert(encrypted.iv.length === 12, 'IV should be 12 bytes');
  assert(encrypted.tag.length === 16, 'Tag should be 16 bytes');

  // Decrypt private key
  const decrypted = await grimlock.decryptPrivateKey(
    encrypted,
    passcodeKey,
    userIdBytes
  );

  // Verify decryption
  assert(decrypted.length === keyPair.privateKey.length, 'Decrypted key size should match');
  assert(arraysEqual(keyPair.privateKey, decrypted), 'Decrypted key should match original');

  // Test with wrong passcode should fail
  const wrongPasscodeKey = await grimlock.derivePasscodeKey('wrong-passcode', kdfParams);
  let decryptionFailed = false;
  try {
    await grimlock.decryptPrivateKey(encrypted, wrongPasscodeKey, userIdBytes);
  } catch (error) {
    decryptionFailed = true;
  }
  assert(decryptionFailed, 'Decryption with wrong passcode should fail');

  // Clean up
  passcodeKey.fill(0);
  wrongPasscodeKey.fill(0);
  decrypted.fill(0);
}

/**
 * Test 3: Server-side message encryption and decryption
 */
async function testServerSideMessageEncryption(): Promise<void> {
  // Setup: User has a key pair
  const userKeyPair = await grimlock.generateKeyPair();

  // Server receives user's public key
  const userPublicKey = userKeyPair.publicKey;

  // Create message payload
  const payload: MessagePayload = {
    userMessage: 'What is the weather today?',
    assistantResponse: 'The weather today is sunny with a high of 75°F.',
    context: {
      model: 'gpt-4',
      timestamp: 1234567890,
    },
  };

  // Create context
  const context: MessageContext = {
    conversationId: 'conv-123',
    messageId: 'msg-456',
  };

  // Server encrypts message before storage
  const encrypted = await grimlock.encryptMessage(payload, userPublicKey, context);

  // Verify encrypted message structure
  assert(encrypted.ephemeralPublicKey.length === 32, 'Ephemeral public key should be 32 bytes');
  assert(encrypted.iv.length === 12, 'IV should be 12 bytes');
  assert(encrypted.tag.length === 16, 'Tag should be 16 bytes');
  assert(encrypted.ciphertext.length > 0, 'Ciphertext should not be empty');

  // Client decrypts message
  const decrypted = await grimlock.decryptMessage(
    encrypted,
    userKeyPair.privateKey,
    context
  );

  // Verify decrypted payload
  assert(decrypted.userMessage === payload.userMessage, 'User message should match');
  assert(decrypted.assistantResponse === payload.assistantResponse, 'Assistant response should match');
  
  if (payload.context && decrypted.context) {
    assert(
      decrypted.context.model === payload.context.model,
      'Context model should match'
    );
    assert(
      decrypted.context.timestamp === payload.context.timestamp,
      'Context timestamp should match'
    );
  }

  // Test with wrong private key should fail
  const wrongKeyPair = await grimlock.generateKeyPair();
  let decryptionFailed = false;
  try {
    await grimlock.decryptMessage(encrypted, wrongKeyPair.privateKey, context);
  } catch (error) {
    decryptionFailed = true;
  }
  assert(decryptionFailed, 'Decryption with wrong private key should fail');
}

/**
 * Test 4: Recovery key generation and usage
 */
async function testRecoveryKey(): Promise<void> {
  // Generate user key pair
  const keyPair = await grimlock.generateKeyPair();

  // Generate recovery key
  const recoveryKey = grimlock.generateRecoveryKey();

  assert(recoveryKey.raw.length === 32, 'Recovery key should be 32 bytes');
  assert(recoveryKey.base64.length > 0, 'Recovery key should have base64 representation');
  assert(typeof recoveryKey.base64 === 'string', 'Base64 should be a string');

  // Derive encryption key from recovery key
  const recoveryEncryptionKey = await grimlock.deriveRecoveryKey(recoveryKey.raw);
  assert(recoveryEncryptionKey.length === 32, 'Recovery encryption key should be 32 bytes');

  // Encrypt private key with recovery key
  const userIdBytes = new TextEncoder().encode('user-123');
  const encrypted = await grimlock.encryptPrivateKey(
    keyPair.privateKey,
    recoveryEncryptionKey,
    userIdBytes
  );

  // Decrypt private key with recovery key
  const decrypted = await grimlock.decryptPrivateKey(
    encrypted,
    recoveryEncryptionKey,
    userIdBytes
  );

  // Verify decryption
  assert(decrypted.length === keyPair.privateKey.length, 'Decrypted key size should match');
  assert(arraysEqual(keyPair.privateKey, decrypted), 'Decrypted key should match original');

  // Clean up
  recoveryEncryptionKey.fill(0);
  decrypted.fill(0);
}

/**
 * Test 5: Version manager
 */
async function testVersionManager(): Promise<void> {
  const manager = getVersionManager();

  // Get latest version
  const latest = manager.getLatestVersion();
  assert(latest === 'v1', 'Latest version should be v1');

  // Get version metadata
  const v1Meta = manager.getVersion('v1');
  assert(v1Meta !== null, 'v1 metadata should exist');
  
  if (v1Meta) {
    assert(v1Meta.version === 'v1', 'Version should be v1');
    assert(v1Meta.algorithms.keyExchange === 'X25519', 'Key exchange should be X25519');
    assert(v1Meta.algorithms.encryption === 'AES-256-GCM', 'Encryption should be AES-256-GCM');
    assert(v1Meta.algorithms.keyDerivation === 'Argon2id-v1', 'KDF should be Argon2id');
  }

  // Check compatibility
  assert(manager.isCompatible('v1', 'v1'), 'v1 should be compatible with v1');

  // Check deprecated status
  assert(!manager.isDeprecated('v1'), 'v1 should not be deprecated');
}

/**
 * Test 6: Serialization and deserialization
 */
async function testSerialization(): Promise<void> {
  // Generate key pair
  const keyPair = await grimlock.generateKeyPair();

  // Serialize to base64
  const serialized = grimlock.serializeKeyPair(keyPair);
  assert(typeof serialized.privateKey === 'string', 'Serialized private key should be string');
  assert(typeof serialized.publicKey === 'string', 'Serialized public key should be string');
  assert(serialized.privateKey.length > 0, 'Serialized private key should not be empty');
  assert(serialized.publicKey.length > 0, 'Serialized public key should not be empty');

  // Deserialize from base64
  const deserialized = grimlock.deserializeKeyPair(serialized);

  // Verify deserialization
  assert(deserialized.privateKey.length === keyPair.privateKey.length, 'Deserialized private key size should match');
  assert(deserialized.publicKey.length === keyPair.publicKey.length, 'Deserialized public key size should match');
  assert(arraysEqual(keyPair.privateKey, deserialized.privateKey), 'Deserialized private key should match original');
  assert(arraysEqual(keyPair.publicKey, deserialized.publicKey), 'Deserialized public key should match original');
}

/**
 * Test 7: ECDH shared secret computation
 */
async function testECDH(): Promise<void> {
  // Import ECDH function - need to access v1 internals
  const { computeSharedSecret } = await import('./versions/v1/ecdh');

  // Generate two key pairs (Alice and Bob)
  const aliceKeyPair = await grimlock.generateKeyPair();
  const bobKeyPair = await grimlock.generateKeyPair();

  // Alice computes shared secret with Bob's public key
  const aliceShared = await computeSharedSecret(
    aliceKeyPair.privateKey,
    bobKeyPair.publicKey
  );

  // Bob computes shared secret with Alice's public key
  const bobShared = await computeSharedSecret(
    bobKeyPair.privateKey,
    aliceKeyPair.publicKey
  );

  // Verify both shared secrets are identical
  assert(aliceShared.length === bobShared.length, 'Shared secret sizes should match');
  assert(arraysEqual(aliceShared, bobShared), 'Shared secrets should be identical');
  assert(aliceShared.length === 32, 'Shared secret should be 32 bytes');

  // Clean up
  aliceShared.fill(0);
  bobShared.fill(0);
}

/**
 * Test 8: Version detection
 */
async function testVersionDetection(): Promise<void> {
  // Test with explicit _version field
  const dataWithVersion = { _version: 'v1', data: 'test' };
  assert(detectVersion(dataWithVersion) === 'v1', 'Should detect v1 from _version field');

  // Test with version in metadata
  const dataWithMetadata = { 
    metadata: { version: 'v1' },
    data: 'test'
  };
  assert(detectVersion(dataWithMetadata) === 'v1', 'Should detect v1 from metadata');

  // Test with no version (should default to v1)
  const dataNoVersion = { data: 'test' };
  assert(detectVersion(dataNoVersion) === 'v1', 'Should default to v1 when no version found');

  // Test getVersionForData
  const api = getVersionForData(dataWithVersion);
  assert(api.version === 'v1', 'Should return v1 API');
}

/**
 * Test 9: Multiple message encryption/decryption
 */
async function testMultipleMessages(): Promise<void> {
  // Setup: User has a key pair
  const userKeyPair = await grimlock.generateKeyPair();

  // Encrypt multiple messages with different contexts
  const messages = [
    {
      payload: {
        userMessage: 'First message',
        assistantResponse: 'First response',
      },
      context: {
        conversationId: 'conv-1',
        messageId: 'msg-1',
      },
    },
    {
      payload: {
        userMessage: 'Second message',
        assistantResponse: 'Second response',
      },
      context: {
        conversationId: 'conv-1',
        messageId: 'msg-2',
      },
    },
    {
      payload: {
        userMessage: 'Third message',
        assistantResponse: 'Third response',
      },
      context: {
        conversationId: 'conv-2',
        messageId: 'msg-1',
      },
    },
  ];

  // Encrypt all messages
  const encrypted = await Promise.all(
    messages.map(({ payload, context }) =>
      grimlock.encryptMessage(payload, userKeyPair.publicKey, context)
    )
  );

  // Decrypt all messages
  const decrypted = await Promise.all(
    encrypted.map((enc, i) =>
      grimlock.decryptMessage(enc, userKeyPair.privateKey, messages[i].context)
    )
  );

  // Verify all messages
  for (let i = 0; i < messages.length; i++) {
    assert(
      decrypted[i].userMessage === messages[i].payload.userMessage,
      `Message ${i} user message should match`
    );
    assert(
      decrypted[i].assistantResponse === messages[i].payload.assistantResponse,
      `Message ${i} assistant response should match`
    );
  }
}

/**
 * Test 10: Constants verification
 */
async function testConstants(): Promise<void> {
  const constants = v1.constants;

  // Verify key sizes
  assert(constants.x25519KeySize === 32, 'X25519 key size should be 32');
  
  // Verify AES-GCM parameters
  assert(constants.aesKeySize === 32, 'AES key size should be 32 (AES-256)');
  assert(constants.aesIvSize === 12, 'AES IV size should be 12');
  assert(constants.aesTagSize === 16, 'AES tag size should be 16');

  // Verify Argon2 parameters
  assert(constants.argon2TimeCost === 4, 'Argon2 time cost should be 4');
  assert(constants.argon2MemoryCost === 131072, 'Argon2 memory cost should be 131072');
  assert(constants.argon2Parallelism === 2, 'Argon2 parallelism should be 2');
  assert(constants.argon2SaltSize === 32, 'Argon2 salt size should be 32');
}

/**
 * Test 11: Edge cases - Empty and large payloads
 */
async function testEdgeCases(): Promise<void> {
  const userKeyPair = await grimlock.generateKeyPair();
  const context: MessageContext = {
    conversationId: 'conv-edge',
    messageId: 'msg-edge',
  };

  // Test with minimal payload
  const minimalPayload: MessagePayload = {
    userMessage: '',
    assistantResponse: '',
  };

  const encryptedMinimal = await grimlock.encryptMessage(
    minimalPayload,
    userKeyPair.publicKey,
    context
  );
  const decryptedMinimal = await grimlock.decryptMessage(
    encryptedMinimal,
    userKeyPair.privateKey,
    context
  );

  assert(decryptedMinimal.userMessage === '', 'Empty user message should be preserved');
  assert(decryptedMinimal.assistantResponse === '', 'Empty assistant response should be preserved');

  // Test with large payload
  const largeText = 'A'.repeat(10000);
  const largePayload: MessagePayload = {
    userMessage: largeText,
    assistantResponse: largeText,
    context: {
      largeArray: Array(100).fill('data'),
    },
  };

  const encryptedLarge = await grimlock.encryptMessage(
    largePayload,
    userKeyPair.publicKey,
    context
  );
  const decryptedLarge = await grimlock.decryptMessage(
    encryptedLarge,
    userKeyPair.privateKey,
    context
  );

  assert(decryptedLarge.userMessage === largeText, 'Large user message should be preserved');
  assert(decryptedLarge.assistantResponse === largeText, 'Large assistant response should be preserved');
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================

async function main(): Promise<void> {
  console.log(`\n${colors.blue}╔════════════════════════════════════════════════════════════╗${colors.reset}`);
  console.log(`${colors.blue}║  Grimlock Crypto Module Test Suite                        ║${colors.reset}`);
  console.log(`${colors.blue}╚════════════════════════════════════════════════════════════╝${colors.reset}\n`);

  const startTime = Date.now();

  // Run all tests
  await runTest('Test 1: Basic Key Pair Generation', testGenerateKeyPair);
  await runTest('Test 2: Passcode-Based Encryption', testPasscodeBasedEncryption);
  await runTest('Test 3: Server-Side Message Encryption', testServerSideMessageEncryption);
  await runTest('Test 4: Recovery Key', testRecoveryKey);
  await runTest('Test 5: Version Manager', testVersionManager);
  await runTest('Test 6: Serialization', testSerialization);
  await runTest('Test 7: ECDH Shared Secret', testECDH);
  await runTest('Test 8: Version Detection', testVersionDetection);
  await runTest('Test 9: Multiple Messages', testMultipleMessages);
  await runTest('Test 10: Constants Verification', testConstants);
  await runTest('Test 11: Edge Cases', testEdgeCases);

  const endTime = Date.now();
  const duration = ((endTime - startTime) / 1000).toFixed(2);

  // Print summary
  console.log(`${colors.blue}════════════════════════════════════════════════════════════${colors.reset}\n`);
  console.log(`${colors.cyan}Test Summary:${colors.reset}`);
  console.log(`  ${colors.green}✓ Passed:${colors.reset} ${testsPassed}`);
  console.log(`  ${colors.red}✗ Failed:${colors.reset} ${testsFailed}`);
  console.log(`  ${colors.yellow}⏱ Duration:${colors.reset} ${duration}s\n`);

  if (testsFailed > 0) {
    console.log(`${colors.red}Some tests failed!${colors.reset}\n`);
    process.exit(1);
  } else {
    console.log(`${colors.green}All tests passed!${colors.reset} 🎉\n`);
    process.exit(0);
  }
}

// Run the test suite (ESM-friendly entrypoint)
// This file is intended to be executed directly via the npm script (`npm test`),
// so we can safely invoke main() unconditionally in ESM.
main().catch((error) => {
  console.error(`${colors.red}Fatal error:${colors.reset}`, error);
  process.exit(1);
});

export {
  runTest,
  assert,
  arraysEqual,
  generateKdfParams,
};
