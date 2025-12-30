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

import { describe, test, expect } from "vitest";
import grimlock, {
  v1,
  getVersionManager,
  detectVersion,
  getVersionForData,
} from "./index";
import type { MessagePayload, MessageContext, KdfParams } from "./types/common";

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
  crypto.getRandomValues(salt);

  return {
    salt,
    argon2Params: {
      timeCost: 4,
      memoryCost: 128 * 1024, // 128MB in KB
      parallelism: 2,
    },
  };
}

describe("Grimlock Crypto Module", () => {
  describe("Key Generation", () => {
    test("should generate valid key pairs", async () => {
      const keyPair = await grimlock.generateKeyPair();

      expect(keyPair.privateKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.privateKey.length).toBe(32);
      expect(keyPair.publicKey.length).toBe(32);
    });

    test("should generate unique key pairs", async () => {
      const keyPair1 = await grimlock.generateKeyPair();
      const keyPair2 = await grimlock.generateKeyPair();

      expect(arraysEqual(keyPair1.privateKey, keyPair2.privateKey)).toBe(false);
      expect(arraysEqual(keyPair1.publicKey, keyPair2.publicKey)).toBe(false);
    });
  });

  describe("Passcode-Based Encryption", () => {
    test("should encrypt and decrypt private key with passcode", async () => {
      const keyPair = await grimlock.generateKeyPair();
      const kdfParams = generateKdfParams();
      const passcode = "my-secure-passcode-123";

      const passcodeKey = await grimlock.derivePasscodeKey(passcode, kdfParams);
      expect(passcodeKey.length).toBe(32);

      const userIdBytes = new TextEncoder().encode("user-123");
      const encrypted = await grimlock.encryptPrivateKey(
        keyPair.privateKey,
        passcodeKey,
        userIdBytes
      );

      expect(encrypted.ciphertext.length).toBeGreaterThan(0);
      expect(encrypted.iv.length).toBe(12);
      expect(encrypted.tag.length).toBe(16);

      const decrypted = await grimlock.decryptPrivateKey(
        encrypted,
        passcodeKey,
        userIdBytes
      );

      expect(decrypted.length).toBe(keyPair.privateKey.length);
      expect(arraysEqual(keyPair.privateKey, decrypted)).toBe(true);

      passcodeKey.fill(0);
      decrypted.fill(0);
    });

    test("should fail to decrypt with wrong passcode", async () => {
      const keyPair = await grimlock.generateKeyPair();
      const kdfParams = generateKdfParams();
      const passcode = "correct-passcode";

      const passcodeKey = await grimlock.derivePasscodeKey(passcode, kdfParams);
      const userIdBytes = new TextEncoder().encode("user-123");
      const encrypted = await grimlock.encryptPrivateKey(
        keyPair.privateKey,
        passcodeKey,
        userIdBytes
      );

      const wrongPasscodeKey = await grimlock.derivePasscodeKey(
        "wrong-passcode",
        kdfParams
      );

      await expect(
        grimlock.decryptPrivateKey(encrypted, wrongPasscodeKey, userIdBytes)
      ).rejects.toThrow();

      passcodeKey.fill(0);
      wrongPasscodeKey.fill(0);
    });
  });

  describe("Message Encryption", () => {
    test("should encrypt and decrypt messages", async () => {
      const userKeyPair = await grimlock.generateKeyPair();
      const userPublicKey = userKeyPair.publicKey;

      const payload: MessagePayload = {
        userMessage: "What is the weather today?",
        assistantResponse: "The weather today is sunny with a high of 75°F.",
        context: {
          model: "gpt-4",
          timestamp: 1234567890,
        },
      };

      const context: MessageContext = {
        conversationId: "conv-123",
        messageId: "msg-456",
      };

      const encrypted = await grimlock.encryptMessage(
        payload,
        userPublicKey,
        context
      );

      expect(encrypted.ephemeralPublicKey.length).toBe(32);
      expect(encrypted.iv.length).toBe(12);
      expect(encrypted.tag.length).toBe(16);
      expect(encrypted.ciphertext.length).toBeGreaterThan(0);

      const decrypted = await grimlock.decryptMessage(
        encrypted,
        userKeyPair.privateKey,
        context
      );

      expect(decrypted.userMessage).toBe(payload.userMessage);
      expect(decrypted.assistantResponse).toBe(payload.assistantResponse);
      expect(decrypted.context?.model).toBe(payload.context?.model);
      expect(decrypted.context?.timestamp).toBe(payload.context?.timestamp);
    });

    test("should fail to decrypt with wrong private key", async () => {
      const userKeyPair = await grimlock.generateKeyPair();
      const wrongKeyPair = await grimlock.generateKeyPair();

      const payload: MessagePayload = {
        userMessage: "Test message",
        assistantResponse: "Test response",
      };

      const context: MessageContext = {
        conversationId: "conv-123",
        messageId: "msg-456",
      };

      const encrypted = await grimlock.encryptMessage(
        payload,
        userKeyPair.publicKey,
        context
      );

      await expect(
        grimlock.decryptMessage(encrypted, wrongKeyPair.privateKey, context)
      ).rejects.toThrow();
    });

    test("should encrypt and decrypt multiple messages", async () => {
      const userKeyPair = await grimlock.generateKeyPair();

      const messages = [
        {
          payload: {
            userMessage: "First message",
            assistantResponse: "First response",
          },
          context: {
            conversationId: "conv-1",
            messageId: "msg-1",
          },
        },
        {
          payload: {
            userMessage: "Second message",
            assistantResponse: "Second response",
          },
          context: {
            conversationId: "conv-1",
            messageId: "msg-2",
          },
        },
        {
          payload: {
            userMessage: "Third message",
            assistantResponse: "Third response",
          },
          context: {
            conversationId: "conv-2",
            messageId: "msg-1",
          },
        },
      ];

      const encrypted = await Promise.all(
        messages.map(({ payload, context }) =>
          grimlock.encryptMessage(payload, userKeyPair.publicKey, context)
        )
      );

      const decrypted = await Promise.all(
        encrypted.map((enc, i) =>
          grimlock.decryptMessage(
            enc,
            userKeyPair.privateKey,
            messages[i].context
          )
        )
      );

      for (let i = 0; i < messages.length; i++) {
        expect(decrypted[i].userMessage).toBe(messages[i].payload.userMessage);
        expect(decrypted[i].assistantResponse).toBe(
          messages[i].payload.assistantResponse
        );
      }
    });
  });

  describe("Recovery Keys", () => {
    test("should generate and use recovery keys", async () => {
      const keyPair = await grimlock.generateKeyPair();
      const recoveryKey = grimlock.generateRecoveryKey();

      expect(recoveryKey.raw.length).toBe(32);
      expect(recoveryKey.base64.length).toBeGreaterThan(0);
      expect(typeof recoveryKey.base64).toBe("string");

      const recoveryEncryptionKey = await grimlock.deriveRecoveryKey(
        recoveryKey.raw
      );
      expect(recoveryEncryptionKey.length).toBe(32);

      const userIdBytes = new TextEncoder().encode("user-123");
      const encrypted = await grimlock.encryptPrivateKey(
        keyPair.privateKey,
        recoveryEncryptionKey,
        userIdBytes
      );

      const decrypted = await grimlock.decryptPrivateKey(
        encrypted,
        recoveryEncryptionKey,
        userIdBytes
      );

      expect(decrypted.length).toBe(keyPair.privateKey.length);
      expect(arraysEqual(keyPair.privateKey, decrypted)).toBe(true);

      recoveryEncryptionKey.fill(0);
      decrypted.fill(0);
    });
  });

  describe("Version Management", () => {
    test("should manage versions correctly", async () => {
      const manager = getVersionManager();
      const latest = manager.getLatestVersion();
      expect(latest).toBe("v1");

      const v1Meta = manager.getVersion("v1");
      expect(v1Meta).not.toBeNull();
      expect(v1Meta?.version).toBe("v1");
      expect(v1Meta?.algorithms.keyExchange).toBe("X25519");
      expect(v1Meta?.algorithms.encryption).toBe("AES-256-GCM");
      expect(v1Meta?.algorithms.keyDerivation).toBe("Argon2id-v1");

      expect(manager.isCompatible("v1", "v1")).toBe(true);
      expect(manager.isDeprecated("v1")).toBe(false);
    });

    test("should detect versions from data", async () => {
      const dataWithVersion = { _version: "v1", data: "test" };
      expect(detectVersion(dataWithVersion)).toBe("v1");

      const dataWithMetadata = {
        metadata: { version: "v1" },
        data: "test",
      };
      expect(detectVersion(dataWithMetadata)).toBe("v1");

      const dataNoVersion = { data: "test" };
      expect(detectVersion(dataNoVersion)).toBe("v1");

      const api = getVersionForData(dataWithVersion);
      expect(api.version).toBe("v1");
    });
  });

  describe("Serialization", () => {
    test("should serialize and deserialize key pairs", async () => {
      const keyPair = await grimlock.generateKeyPair();

      const serialized = grimlock.serializeKeyPair(keyPair);
      expect(typeof serialized.privateKey).toBe("string");
      expect(typeof serialized.publicKey).toBe("string");
      expect(serialized.privateKey.length).toBeGreaterThan(0);
      expect(serialized.publicKey.length).toBeGreaterThan(0);

      const deserialized = grimlock.deserializeKeyPair(serialized);

      expect(deserialized.privateKey.length).toBe(keyPair.privateKey.length);
      expect(deserialized.publicKey.length).toBe(keyPair.publicKey.length);
      expect(arraysEqual(keyPair.privateKey, deserialized.privateKey)).toBe(
        true
      );
      expect(arraysEqual(keyPair.publicKey, deserialized.publicKey)).toBe(true);
    });
  });

  describe("ECDH Operations", () => {
    test("should compute shared secrets correctly", async () => {
      const { computeSharedSecret } = await import("./versions/v1/ecdh");

      const aliceKeyPair = await grimlock.generateKeyPair();
      const bobKeyPair = await grimlock.generateKeyPair();

      const aliceShared = await computeSharedSecret(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const bobShared = await computeSharedSecret(
        bobKeyPair.privateKey,
        aliceKeyPair.publicKey
      );

      expect(aliceShared.length).toBe(bobShared.length);
      expect(arraysEqual(aliceShared, bobShared)).toBe(true);
      expect(aliceShared.length).toBe(32);

      aliceShared.fill(0);
      bobShared.fill(0);
    });
  });

  describe("Constants", () => {
    test("should have correct constant values", async () => {
      const constants = v1.constants;

      expect(constants.x25519KeySize).toBe(32);
      expect(constants.aesKeySize).toBe(32);
      expect(constants.aesIvSize).toBe(12);
      expect(constants.aesTagSize).toBe(16);
      expect(constants.argon2TimeCost).toBe(4);
      expect(constants.argon2MemoryCost).toBe(131072);
      expect(constants.argon2Parallelism).toBe(2);
      expect(constants.argon2SaltSize).toBe(32);
    });
  });

  describe("Edge Cases", () => {
    test("should handle empty payloads", async () => {
      const userKeyPair = await grimlock.generateKeyPair();
      const context: MessageContext = {
        conversationId: "conv-edge",
        messageId: "msg-edge",
      };

      const minimalPayload: MessagePayload = {
        userMessage: "",
        assistantResponse: "",
      };

      const encrypted = await grimlock.encryptMessage(
        minimalPayload,
        userKeyPair.publicKey,
        context
      );
      const decrypted = await grimlock.decryptMessage(
        encrypted,
        userKeyPair.privateKey,
        context
      );

      expect(decrypted.userMessage).toBe("");
      expect(decrypted.assistantResponse).toBe("");
    });

    test("should handle large payloads", async () => {
      const userKeyPair = await grimlock.generateKeyPair();
      const context: MessageContext = {
        conversationId: "conv-edge",
        messageId: "msg-edge",
      };

      const largeText = "A".repeat(10000);
      const largePayload: MessagePayload = {
        userMessage: largeText,
        assistantResponse: largeText,
        context: {
          largeArray: Array(100).fill("data"),
        },
      };

      const encrypted = await grimlock.encryptMessage(
        largePayload,
        userKeyPair.publicKey,
        context
      );
      const decrypted = await grimlock.decryptMessage(
        encrypted,
        userKeyPair.privateKey,
        context
      );

      expect(decrypted.userMessage).toBe(largeText);
      expect(decrypted.assistantResponse).toBe(largeText);
    });
  });
});
