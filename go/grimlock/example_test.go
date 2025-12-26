package grimlock_test

import (
	"fmt"
	"testing"

	"github.com/privyy-io/grimlock/go/grimlock"
	"github.com/privyy-io/grimlock/go/grimlock/types"
	v1 "github.com/privyy-io/grimlock/go/grimlock/v1"
)

// Example of basic key generation and encryption
func ExampleGenerateKeyPair() {
	keyPair, err := grimlock.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Generated key pair with public key size: %d bytes\n", len(keyPair.PublicKey))
	// Output: Generated key pair with public key size: 32 bytes
}

// Example of passcode-based private key encryption
func TestPasscodeBasedEncryption(t *testing.T) {
	// Generate user key pair
	keyPair, err := grimlock.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Generate KDF parameters
	kdfParams, err := grimlock.GenerateDefaultKdfParams()
	if err != nil {
		t.Fatal(err)
	}

	// User enters passcode
	passcode := "my-secure-passcode-123"

	// Derive encryption key from passcode
	passcodeKey, err := grimlock.DerivePasscodeKey(passcode, kdfParams)
	if err != nil {
		t.Fatal(err)
	}
	defer grimlock.Default.SecureErase(passcodeKey)

	// Encrypt private key
	encrypted, err := grimlock.EncryptPrivateKey(
		keyPair.PrivateKey,
		passcodeKey,
		[]byte("user-123"),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt private key
	decrypted, err := grimlock.DecryptPrivateKey(
		&encrypted.EncryptedPrivateKey,
		passcodeKey,
		[]byte("user-123"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer grimlock.Default.SecureErase(decrypted)

	// Verify decryption
	if len(decrypted) != len(keyPair.PrivateKey) {
		t.Errorf("Decrypted key size mismatch: expected %d, got %d",
			len(keyPair.PrivateKey), len(decrypted))
	}

	for i := range keyPair.PrivateKey {
		if keyPair.PrivateKey[i] != decrypted[i] {
			t.Fatal("Decrypted key does not match original")
		}
	}

	t.Log("✓ Passcode-based encryption/decryption successful")
}

// Example of server-side message encryption (Algorithm C)
func TestServerSideMessageEncryption(t *testing.T) {
	// Setup: User has a key pair
	userKeyPair, err := grimlock.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Server receives user's public key
	userPublicKey := userKeyPair.PublicKey

	// Create message payload
	payload := types.MessagePayload{
		UserMessage:       "What is the weather today?",
		AssistantResponse: "The weather today is sunny with a high of 75°F.",
		OptionalContext: map[string]interface{}{
			"model":     "gpt-4",
			"timestamp": 1234567890,
		},
	}

	// Create context
	context := types.MessageContext{
		ConversationID: "conv-123",
		MessageID:      "msg-456",
	}

	// Server encrypts message before storage
	encrypted, err := grimlock.EncryptMessage(payload, userPublicKey, context)
	if err != nil {
		t.Fatal(err)
	}

	// Verify encrypted message structure
	if len(encrypted.EphemeralPublicKey) != v1.Constants.X25519PublicKeySize {
		t.Errorf("Invalid ephemeral public key size: %d", len(encrypted.EphemeralPublicKey))
	}
	if len(encrypted.IV) != v1.Constants.GCMNonceSize {
		t.Errorf("Invalid IV size: %d", len(encrypted.IV))
	}
	if len(encrypted.Tag) != v1.Constants.GCMTagSize {
		t.Errorf("Invalid tag size: %d", len(encrypted.Tag))
	}
	if len(encrypted.Ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}

	// Client decrypts message
	decrypted, err := grimlock.DecryptMessage(
		&encrypted.EncryptedMessage,
		userKeyPair.PrivateKey,
		context,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Verify decrypted payload
	if decrypted.UserMessage != payload.UserMessage {
		t.Errorf("User message mismatch: expected %q, got %q",
			payload.UserMessage, decrypted.UserMessage)
	}
	if decrypted.AssistantResponse != payload.AssistantResponse {
		t.Errorf("Assistant response mismatch: expected %q, got %q",
			payload.AssistantResponse, decrypted.AssistantResponse)
	}

	t.Log("✓ Server-side message encryption/decryption successful")
}

// Example of recovery key usage
func TestRecoveryKey(t *testing.T) {
	// Generate user key pair
	keyPair, err := grimlock.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Generate recovery key
	recoveryKey, err := grimlock.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt private key with recovery key
	encrypted, err := v1.V1.EncryptPrivateKeyWithRecoveryKey(
		keyPair.PrivateKey,
		recoveryKey.Key,
		[]byte("user-123"),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt private key with recovery key
	decrypted, err := v1.V1.DecryptPrivateKeyWithRecoveryKey(
		&encrypted.EncryptedPrivateKey,
		recoveryKey.Key,
		[]byte("user-123"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer grimlock.Default.SecureErase(decrypted)

	// Verify decryption
	if len(decrypted) != len(keyPair.PrivateKey) {
		t.Errorf("Decrypted key size mismatch: expected %d, got %d",
			len(keyPair.PrivateKey), len(decrypted))
	}

	for i := range keyPair.PrivateKey {
		if keyPair.PrivateKey[i] != decrypted[i] {
			t.Fatal("Decrypted key does not match original")
		}
	}

	t.Log("✓ Recovery key encryption/decryption successful")
}

// Example of version manager usage
func TestVersionManager(t *testing.T) {
	manager := grimlock.GetVersionManager()

	// Get latest version
	latest := manager.GetLatestVersion()
	if latest != "v1" {
		t.Errorf("Expected latest version to be v1, got %s", latest)
	}

	// Get version metadata
	v1Meta, err := manager.GetVersion("v1")
	if err != nil {
		t.Fatal(err)
	}

	// Verify v1 metadata
	if v1Meta.Version != "v1" {
		t.Errorf("Expected version v1, got %s", v1Meta.Version)
	}
	if v1Meta.Algorithms.KeyExchange != "X25519" {
		t.Errorf("Expected X25519, got %s", v1Meta.Algorithms.KeyExchange)
	}
	if v1Meta.Algorithms.Encryption != "AES-256-GCM" {
		t.Errorf("Expected AES-256-GCM, got %s", v1Meta.Algorithms.Encryption)
	}

	// Check compatibility
	if !manager.IsCompatible("v1", "v1") {
		t.Error("v1 should be compatible with v1")
	}

	// Check deprecated status
	deprecated, err := manager.IsDeprecated("v1")
	if err != nil {
		t.Fatal(err)
	}
	if deprecated {
		t.Error("v1 should not be deprecated")
	}

	t.Log("✓ Version manager working correctly")
}

// Example of serialization utilities
func TestSerialization(t *testing.T) {
	// Generate key pair
	keyPair, err := grimlock.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Serialize to base64
	serialized := v1.V1.SerializeKeyPair(&keyPair.KeyPair)
	if serialized.PrivateKey == "" || serialized.PublicKey == "" {
		t.Error("Serialized key pair has empty fields")
	}

	// Deserialize from base64
	deserialized, err := v1.V1.DeserializeKeyPair(serialized)
	if err != nil {
		t.Fatal(err)
	}

	// Verify deserialization
	if len(deserialized.PrivateKey) != len(keyPair.PrivateKey) {
		t.Errorf("Deserialized private key size mismatch")
	}
	if len(deserialized.PublicKey) != len(keyPair.PublicKey) {
		t.Errorf("Deserialized public key size mismatch")
	}

	for i := range keyPair.PrivateKey {
		if keyPair.PrivateKey[i] != deserialized.PrivateKey[i] {
			t.Fatal("Deserialized private key does not match original")
		}
	}
	for i := range keyPair.PublicKey {
		if keyPair.PublicKey[i] != deserialized.PublicKey[i] {
			t.Fatal("Deserialized public key does not match original")
		}
	}

	t.Log("✓ Serialization/deserialization successful")
}

// Example of ECDH computation
func TestECDH(t *testing.T) {
	// Generate two key pairs (Alice and Bob)
	aliceKeyPair, err := grimlock.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	bobKeyPair, err := grimlock.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Alice computes shared secret with Bob's public key
	aliceShared, err := grimlock.ComputeSharedSecret(
		aliceKeyPair.PrivateKey,
		bobKeyPair.PublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer grimlock.Default.SecureErase(aliceShared)

	// Bob computes shared secret with Alice's public key
	bobShared, err := grimlock.ComputeSharedSecret(
		bobKeyPair.PrivateKey,
		aliceKeyPair.PublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer grimlock.Default.SecureErase(bobShared)

	// Verify both shared secrets are identical
	if len(aliceShared) != len(bobShared) {
		t.Fatalf("Shared secret size mismatch: Alice=%d, Bob=%d",
			len(aliceShared), len(bobShared))
	}

	for i := range aliceShared {
		if aliceShared[i] != bobShared[i] {
			t.Fatal("Shared secrets do not match")
		}
	}

	t.Log("✓ ECDH computation successful")
}

// Benchmark key pair generation
func BenchmarkGenerateKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := grimlock.GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark Argon2id key derivation
func BenchmarkDerivePasscodeKey(b *testing.B) {
	kdfParams, err := grimlock.GenerateDefaultKdfParams()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, err := grimlock.DerivePasscodeKey("test-passcode", kdfParams)
		if err != nil {
			b.Fatal(err)
		}
		grimlock.Default.SecureErase(key)
	}
}

// Benchmark message encryption
func BenchmarkEncryptMessage(b *testing.B) {
	keyPair, err := grimlock.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	payload := types.MessagePayload{
		UserMessage:       "Test message",
		AssistantResponse: "Test response",
	}

	context := types.MessageContext{
		ConversationID: "conv-123",
		MessageID:      "msg-456",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := grimlock.EncryptMessage(payload, keyPair.PublicKey, context)
		if err != nil {
			b.Fatal(err)
		}
	}
}
