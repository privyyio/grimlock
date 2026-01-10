"""Unit tests for Grimlock v1 operations."""

import pytest

from grimlock import v1
from grimlock.types.common import (
    Argon2Params,
    KdfParams,
    MessageContext,
    MessagePayload,
)


class TestKeyGeneration:
    """Tests for key pair generation."""

    def test_generate_key_pair(self):
        """Test key pair generation."""
        key_pair = v1.generate_key_pair()
        assert key_pair is not None
        assert len(key_pair.private_key) == 32
        assert len(key_pair.public_key) == 32
        assert key_pair._version == "v1"

    def test_validate_key_pair(self):
        """Test key pair validation."""
        key_pair = v1.generate_key_pair()
        # Should not raise
        v1.validate_key_pair(key_pair)

    def test_validate_key_pair_invalid_size(self):
        """Test key pair validation with invalid size."""
        from grimlock.types.common import KeyPair

        invalid_key_pair = KeyPair(
            private_key=b"x" * 31,  # Wrong size
            public_key=b"y" * 32,
        )
        with pytest.raises(ValueError):
            v1.validate_key_pair(invalid_key_pair)


class TestKeyDerivation:
    """Tests for key derivation."""

    def test_derive_passcode_key(self):
        """Test passcode key derivation."""
        passcode = "MySecurePasscode123!"
        salt = v1.generate_salt()
        params = KdfParams(
            salt=salt,
            argon2_params=Argon2Params(
                time_cost=4,
                memory_cost=128 * 1024,
                parallelism=2,
            ),
        )
        derived_key = v1.derive_passcode_key(passcode, params)
        assert len(derived_key) == 32

    def test_derive_recovery_key(self):
        """Test recovery key derivation."""
        recovery_key_bytes = b"x" * 32
        derived_key = v1.derive_recovery_key(recovery_key_bytes)
        assert len(derived_key) == 32

    def test_derive_recovery_key_invalid_size(self):
        """Test recovery key derivation with invalid size."""
        invalid_recovery_key = b"x" * 31
        with pytest.raises(ValueError):
            v1.derive_recovery_key(invalid_recovery_key)

    def test_generate_salt(self):
        """Test salt generation."""
        salt = v1.generate_salt()
        assert len(salt) == 32

    def test_generate_default_kdf_params(self):
        """Test default KDF parameters generation."""
        params = v1.generate_default_kdf_params()
        assert len(params.salt) == 32
        assert params.argon2_params.time_cost == 4
        assert params.argon2_params.memory_cost == 128 * 1024
        assert params.argon2_params.parallelism == 2


class TestPrivateKeyEncryption:
    """Tests for private key encryption/decryption."""

    def test_encrypt_decrypt_private_key(self):
        """Test private key encryption and decryption."""
        private_key = b"x" * 32
        encryption_key = b"y" * 32
        aad = b"test-aad"

        encrypted = v1.encrypt_private_key(private_key, encryption_key, aad)
        assert encrypted is not None
        assert len(encrypted.iv) == 12
        assert len(encrypted.tag) == 16
        assert len(encrypted.ciphertext) > 0

        decrypted = v1.decrypt_private_key(encrypted, encryption_key, aad)
        assert decrypted == private_key

    def test_encrypt_private_key_invalid_size(self):
        """Test private key encryption with invalid key size."""
        private_key = b"x" * 31  # Wrong size
        encryption_key = b"y" * 32
        with pytest.raises(ValueError):
            v1.encrypt_private_key(private_key, encryption_key, b"")


class TestMessageEncryption:
    """Tests for message encryption/decryption."""

    def test_encrypt_decrypt_message(self):
        """Test message encryption and decryption."""
        # Generate user key pair
        user_key_pair = v1.generate_key_pair()

        payload = MessagePayload(
            user_message="Hello, this is a test message!",
            assistant_response="I understand. This is a response.",
            context={"timestamp": "2024-01-15T10:30:00Z", "metadata": "test"},
        )
        context = MessageContext(
            conversation_id="conv-123",
            message_id="msg-456",
        )

        encrypted = v1.encrypt_message(payload, user_key_pair.public_key, context)
        assert encrypted is not None
        assert len(encrypted.ephemeral_public_key) == 32
        assert len(encrypted.iv) == 12
        assert len(encrypted.tag) == 16
        assert len(encrypted.ciphertext) > 0
        assert encrypted._version == "v1"

        decrypted = v1.decrypt_message(
            encrypted, user_key_pair.private_key, context
        )
        assert decrypted.user_message == payload.user_message
        assert decrypted.assistant_response == payload.assistant_response
        assert decrypted.context == payload.context


class TestECDH:
    """Tests for ECDH operations."""

    def test_compute_shared_secret(self):
        """Test ECDH shared secret computation."""
        alice_key_pair = v1.generate_key_pair()
        bob_key_pair = v1.generate_key_pair()

        # Alice computes shared secret with Bob's public key
        shared_secret_alice = v1.compute_shared_secret(
            alice_key_pair.private_key, bob_key_pair.public_key
        )

        # Bob computes shared secret with Alice's public key
        shared_secret_bob = v1.compute_shared_secret(
            bob_key_pair.private_key, alice_key_pair.public_key
        )

        # Shared secrets should match
        assert shared_secret_alice == shared_secret_bob
        assert len(shared_secret_alice) == 32


class TestRecoveryKey:
    """Tests for recovery key operations."""

    def test_generate_recovery_key(self):
        """Test recovery key generation."""
        recovery_key = v1.generate_recovery_key()
        assert recovery_key is not None
        assert len(recovery_key.raw) == 32
        assert len(recovery_key.base64) == 44  # Base64 encoding of 32 bytes
        # Mnemonic is optional, so we don't assert it

    def test_encrypt_decrypt_with_recovery_key(self):
        """Test private key encryption/decryption with recovery key."""
        private_key = b"x" * 32
        recovery_key = v1.generate_recovery_key()
        aad = b"test-aad"

        encrypted = v1.encrypt_private_key_with_recovery_key(
            private_key, recovery_key.raw, aad
        )
        assert encrypted is not None

        decrypted = v1.decrypt_private_key_with_recovery_key(
            encrypted, recovery_key.raw, aad
        )
        assert decrypted == private_key

    def test_validate_recovery_key(self):
        """Test recovery key validation."""
        recovery_key = v1.generate_recovery_key()
        # Should not raise
        v1.validate_recovery_key(recovery_key.raw)

    def test_validate_recovery_key_invalid_size(self):
        """Test recovery key validation with invalid size."""
        invalid_recovery_key = b"x" * 31
        with pytest.raises(ValueError):
            v1.validate_recovery_key(invalid_recovery_key)

    def test_validate_recovery_key_all_zeros(self):
        """Test recovery key validation with all zeros."""
        zero_recovery_key = b"\x00" * 32
        with pytest.raises(ValueError):
            v1.validate_recovery_key(zero_recovery_key)


class TestSerialization:
    """Tests for serialization utilities."""

    def test_serialize_deserialize_key_pair(self):
        """Test key pair serialization and deserialization."""
        key_pair = v1.generate_key_pair()
        serialized = v1.serialize_key_pair(key_pair)
        assert serialized.private_key is not None
        assert serialized.public_key is not None

        deserialized = v1.deserialize_key_pair(serialized)
        assert deserialized.private_key == key_pair.private_key
        assert deserialized.public_key == key_pair.public_key
