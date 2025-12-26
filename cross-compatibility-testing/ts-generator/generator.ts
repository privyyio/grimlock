/**
 * TypeScript Test Data Generator for Cross-Compatibility Testing
 * 
 * Generates test data using TypeScript grimlock implementation
 * to be verified by Go grimlock implementation
 */

import * as fs from 'fs';
import * as path from 'path';
import grimlock from '../../typescript/grimlock';

interface TestData {
  keyPair: {
    privateKey: string;
    publicKey: string;
  };
  passcodeDerivation: {
    passcode: string;
    salt: string;
    params: {
      timeCost: number;
      memoryCost: number;
      parallelism: number;
    };
    derivedKey: string;
  };
  recoveryKeyDerivation: {
    recoveryKeyBytes: string;
    derivedKey: string;
  };
  privateKeyEncryption: {
    privateKey: string;
    encryptionKey: string;
    aad: string;
    encrypted: {
      iv: string;
      tag: string;
      ciphertext: string;
    };
  };
  messageEncryption: {
    payload: {
      userMessage: string;
      assistantResponse: string;
      optionalContext: Record<string, unknown>;
    };
    userKeyPair: {
      privateKey: string;
      publicKey: string;
    };
    context: {
      conversationId: string;
      messageId: string;
    };
    encrypted: {
      ephemeralPublicKey: string;
      iv: string;
      tag: string;
      ciphertext: string;
    };
  };
  ecdhTest: {
    alicePrivateKey: string;
    alicePublicKey: string;
    bobPrivateKey: string;
    bobPublicKey: string;
    sharedSecret: string;
  };
  recoveryKeyTest: {
    recoveryKey: {
      key: string;
      mnemonic: string;
    };
    privateKey: string;
    aad: string;
    encrypted: {
      iv: string;
      tag: string;
      ciphertext: string;
    };
  };
}

// Helper to convert Uint8Array to base64
function toBase64(data: Uint8Array): string {
  return Buffer.from(data).toString('base64');
}

// Helper to convert string to Uint8Array
function fromString(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

async function generateTestData(): Promise<void> {
  console.log('Generating TypeScript test data...');
  
  const testData: TestData = {} as TestData;

  // 1. Key Generation Test
  console.log('Generating key pair...');
  const keyPair = await grimlock.generateKeyPair();
  testData.keyPair = {
    privateKey: toBase64(keyPair.privateKey),
    publicKey: toBase64(keyPair.publicKey),
  };

  // 2. Passcode Key Derivation Test
  console.log('Deriving passcode key...');
  const passcode = 'MySecurePasscode123!';
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const kdfParams = {
    salt,
    argon2Params: {
      timeCost: 4,
      memoryCost: 128 * 1024, // 128MB
      parallelism: 2,
    },
  };
  const derivedKey = await grimlock.derivePasscodeKey(passcode, kdfParams);
  testData.passcodeDerivation = {
    passcode,
    salt: toBase64(salt),
    params: {
      timeCost: kdfParams.argon2Params.timeCost,
      memoryCost: kdfParams.argon2Params.memoryCost,
      parallelism: kdfParams.argon2Params.parallelism,
    },
    derivedKey: toBase64(derivedKey),
  };

  // 3. Recovery Key Derivation Test
  console.log('Deriving recovery key...');
  const recoveryKey = await grimlock.generateRecoveryKey();
  const recoveryDerivedKey = await grimlock.deriveRecoveryKey(recoveryKey.raw);
  testData.recoveryKeyDerivation = {
    recoveryKeyBytes: toBase64(recoveryKey.raw),
    derivedKey: toBase64(recoveryDerivedKey),
  };

  // 4. Private Key Encryption Test
  console.log('Encrypting private key...');
  const privateKeyToEncrypt = keyPair.privateKey;
  const encryptionKey = derivedKey; // Use the derived key from passcode
  const aad = fromString('user@example.com');
  const encryptedPrivateKey = await grimlock.encryptPrivateKey(
    privateKeyToEncrypt,
    encryptionKey,
    aad
  );
  testData.privateKeyEncryption = {
    privateKey: toBase64(privateKeyToEncrypt),
    encryptionKey: toBase64(encryptionKey),
    aad: toBase64(aad),
    encrypted: {
      iv: toBase64(encryptedPrivateKey.iv),
      tag: toBase64(encryptedPrivateKey.tag),
      ciphertext: toBase64(encryptedPrivateKey.ciphertext),
    },
  };

  // 5. Message Encryption Test
  console.log('Encrypting message...');
  const userKeyPair = await grimlock.generateKeyPair();
  const payload = {
    userMessage: 'Hello, this is a test message!',
    assistantResponse: 'I understand. This is a response.',
    context: {
      timestamp: '2024-01-15T10:30:00Z',
      metadata: 'test',
    },
  };
  const context = {
    conversationId: 'conv-123',
    messageId: 'msg-456',
  };
  const encryptedMessage = await grimlock.encryptMessage(
    payload,
    userKeyPair.publicKey,
    context
  );
  testData.messageEncryption = {
    payload: {
      userMessage: payload.userMessage,
      assistantResponse: payload.assistantResponse,
      optionalContext: payload.context,
    },
    userKeyPair: {
      privateKey: toBase64(userKeyPair.privateKey),
      publicKey: toBase64(userKeyPair.publicKey),
    },
    context: {
      conversationId: context.conversationId,
      messageId: context.messageId,
    },
    encrypted: {
      ephemeralPublicKey: toBase64(encryptedMessage.ephemeralPublicKey),
      iv: toBase64(encryptedMessage.iv),
      tag: toBase64(encryptedMessage.tag),
      ciphertext: toBase64(encryptedMessage.ciphertext),
    },
  };

  // 6. ECDH Test
  console.log('Computing shared secret...');
  const aliceKeyPair = await grimlock.generateKeyPair();
  const bobKeyPair = await grimlock.generateKeyPair();
  
  // Import ECDH function
  const { computeSharedSecret } = await import('../../typescript/grimlock/versions/v1/ecdh');
  const sharedSecret = await computeSharedSecret(
    aliceKeyPair.privateKey,
    bobKeyPair.publicKey
  );
  testData.ecdhTest = {
    alicePrivateKey: toBase64(aliceKeyPair.privateKey),
    alicePublicKey: toBase64(aliceKeyPair.publicKey),
    bobPrivateKey: toBase64(bobKeyPair.privateKey),
    bobPublicKey: toBase64(bobKeyPair.publicKey),
    sharedSecret: toBase64(sharedSecret),
  };

  // 7. Recovery Key Test
  console.log('Testing recovery key encryption...');
  const testRecoveryKey = await grimlock.generateRecoveryKey();
  const privateKeyForRecovery = keyPair.privateKey;
  const aadForRecovery = fromString('recovery@example.com');
  const recoveryEncryptionKey = await grimlock.deriveRecoveryKey(testRecoveryKey.raw);
  const encryptedWithRecovery = await grimlock.encryptPrivateKey(
    privateKeyForRecovery,
    recoveryEncryptionKey,
    aadForRecovery
  );
  testData.recoveryKeyTest = {
    recoveryKey: {
      key: toBase64(testRecoveryKey.raw),
      mnemonic: testRecoveryKey.mnemonic || '',
    },
    privateKey: toBase64(privateKeyForRecovery),
    aad: toBase64(aadForRecovery),
    encrypted: {
      iv: toBase64(encryptedWithRecovery.iv),
      tag: toBase64(encryptedWithRecovery.tag),
      ciphertext: toBase64(encryptedWithRecovery.ciphertext),
    },
  };

  // Clean up sensitive data (best effort in JavaScript)
  keyPair.privateKey.fill(0);
  derivedKey.fill(0);
  recoveryDerivedKey.fill(0);
  encryptionKey.fill(0);
  userKeyPair.privateKey.fill(0);
  aliceKeyPair.privateKey.fill(0);
  bobKeyPair.privateKey.fill(0);
  sharedSecret.fill(0);
  recoveryEncryptionKey.fill(0);

  // Write to JSON file
  const outputPath = path.join(__dirname, '../test-data/ts-generated.json');
  const outputDir = path.dirname(outputPath);
  
  // Create directory if it doesn't exist
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  
  fs.writeFileSync(outputPath, JSON.stringify(testData, null, 2));
  console.log(`✅ Test data generated successfully: ${outputPath}`);
}

// Run the generator
generateTestData().catch((error) => {
  console.error('❌ Failed to generate test data:', error);
  process.exit(1);
});
