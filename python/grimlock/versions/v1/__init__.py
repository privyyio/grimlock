"""V1 API Implementation for Grimlock crypto module.

This is the complete v1 API that follows the protocol specification.
All operations use the v1 constants and algorithms.
"""

import os
from typing import Optional

from ...types.common import (
    EncryptedMessage,
    EncryptedPrivateKey,
    KeyPair,
    KdfParams,
    MessageContext,
    MessagePayload,
    RecoveryKey,
    SerializedKeyPair,
)
from ...types.v1 import EncryptedMessageV1
from ...utils.memory_security import secure_erase
from ...utils.serialization import deserialize_key_pair, serialize_key_pair
from .constants import CRYPTO_CONSTANTS_V1
from .ecdh import compute_shared_secret
from .encryption import (
    create_metadata_aad,
    decrypt_message_payload,
    decrypt_private_key,
    encrypt_message_payload,
    encrypt_private_key,
)
from .key_derivation import (
    derive_message_key,
    derive_passcode_key,
    derive_recovery_key,
    generate_default_kdf_params,
    generate_salt,
)
from .key_generation import generate_key_pair, validate_key_pair
from .recovery_key import (
    decrypt_private_key_with_recovery_key,
    encrypt_private_key_with_recovery_key,
    generate_recovery_key,
    validate_recovery_key,
)


class V1API:
    """V1 API implementation."""

    def __init__(self):
        self.version = "v1"
        self.constants = CRYPTO_CONSTANTS_V1

    # Key Generation
    def generate_key_pair(self) -> KeyPair:
        """Generate a new X25519 key pair."""
        return generate_key_pair()

    def validate_key_pair(self, key_pair: KeyPair) -> None:
        """Validate that a key pair is well-formed."""
        validate_key_pair(key_pair)

    # Key Derivation
    def derive_passcode_key(self, passcode: str, params: KdfParams) -> bytes:
        """Derive a key from a passcode using Argon2id."""
        return derive_passcode_key(passcode, params)

    def derive_recovery_key(self, recovery_key_bytes: bytes) -> bytes:
        """Derive a key from recovery key bytes using HKDF-SHA512."""
        return derive_recovery_key(recovery_key_bytes)

    def generate_salt(self) -> bytes:
        """Generate a random salt for key derivation."""
        return generate_salt()

    def generate_default_kdf_params(self) -> KdfParams:
        """Generate default KDF parameters with a new random salt."""
        return generate_default_kdf_params()

    # Private Key Operations
    def encrypt_private_key(
        self, private_key: bytes, encryption_key: bytes, aad: Optional[bytes] = None
    ) -> EncryptedPrivateKey:
        """Encrypt a private key using AES-256-GCM."""
        if aad is None:
            aad = b""
        return encrypt_private_key(private_key, encryption_key, aad)

    def decrypt_private_key(
        self,
        encrypted: EncryptedPrivateKey,
        encryption_key: bytes,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt a private key using AES-256-GCM."""
        if aad is None:
            aad = b""
        return decrypt_private_key(encrypted, encryption_key, aad)

    # Message Operations
    def encrypt_message(
        self,
        payload: MessagePayload,
        user_public_key: bytes,
        context: MessageContext,
    ) -> EncryptedMessageV1:
        """Encrypt a message payload using ephemeral key ECDH + AES-256-GCM."""
        # Step 1: Generate ephemeral key pair
        ephemeral_key_pair = generate_key_pair()

        try:
            # Step 2: Compute shared secret using ECDH
            shared_secret = compute_shared_secret(
                ephemeral_key_pair.private_key, user_public_key
            )

            try:
                # Step 3: Derive message key from shared secret (match Go format)
                context_string = f"{context.conversation_id}||{context.message_id}"
                message_key = derive_message_key(shared_secret, context_string)

                try:
                    # Step 4: Generate random IV
                    iv = os.urandom(CRYPTO_CONSTANTS_V1.aes_iv_size)

                    # Step 5: Create metadata as AAD (additional authenticated data)
                    metadata = create_metadata_aad(context)

                    # Step 6: Encrypt payload with AAD
                    ciphertext, tag = encrypt_message_payload(
                        payload, message_key, iv, metadata
                    )

                    # Step 7: Securely erase ephemeral private key and derived keys
                    secure_erase(bytearray(ephemeral_key_pair.private_key))
                    secure_erase(bytearray(shared_secret))
                    secure_erase(bytearray(message_key))

                    from ...types.v1 import new_encrypted_message_v1

                    return new_encrypted_message_v1(
                        ephemeral_key_pair.public_key, iv, tag, ciphertext
                    )
                finally:
                    # Best-effort cleanup
                    if isinstance(message_key, bytearray):
                        secure_erase(message_key)
            finally:
                # Best-effort cleanup
                if isinstance(shared_secret, bytearray):
                    secure_erase(shared_secret)
        finally:
            # Best-effort cleanup
            if isinstance(ephemeral_key_pair.private_key, bytearray):
                secure_erase(bytearray(ephemeral_key_pair.private_key))

    def decrypt_message(
        self,
        encrypted: EncryptedMessage,
        user_private_key: bytes,
        context: MessageContext,
        metadata: Optional[bytes] = None,
    ) -> MessagePayload:
        """Decrypt a message using user private key and ECDH."""
        # Step 1: Compute shared secret using ECDH
        shared_secret = compute_shared_secret(
            user_private_key, encrypted.ephemeral_public_key
        )

        try:
            # Step 2: Derive message key from shared secret (match Go format)
            context_string = f"{context.conversation_id}||{context.message_id}"
            message_key = derive_message_key(shared_secret, context_string)

            try:
                # Step 3: Create metadata as AAD if not provided
                aad = metadata if metadata is not None else create_metadata_aad(context)

                # Step 4: Decrypt payload with AAD
                payload = decrypt_message_payload(
                    encrypted.ciphertext,
                    message_key,
                    encrypted.iv,
                    encrypted.tag,
                    aad,
                )

                # Step 5: Securely erase derived keys
                secure_erase(bytearray(shared_secret))
                secure_erase(bytearray(message_key))

                return payload
            finally:
                # Best-effort cleanup
                if isinstance(message_key, bytearray):
                    secure_erase(message_key)
        finally:
            # Best-effort cleanup
            if isinstance(shared_secret, bytearray):
                secure_erase(bytearray(shared_secret))

    # Recovery Key
    def generate_recovery_key(self) -> RecoveryKey:
        """Generate a new cryptographically secure recovery key."""
        return generate_recovery_key()

    def encrypt_private_key_with_recovery_key(
        self, private_key: bytes, recovery_key: bytes, aad: Optional[bytes] = None
    ):
        """Encrypt a private key using a recovery key."""
        if aad is None:
            aad = b""
        return encrypt_private_key_with_recovery_key(private_key, recovery_key, aad)

    def decrypt_private_key_with_recovery_key(
        self,
        encrypted: EncryptedPrivateKey,
        recovery_key: bytes,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt a private key using a recovery key."""
        if aad is None:
            aad = b""
        return decrypt_private_key_with_recovery_key(encrypted, recovery_key, aad)

    def validate_recovery_key(self, recovery_key: bytes) -> None:
        """Validate that a recovery key is well-formed."""
        validate_recovery_key(recovery_key)

    # ECDH Operations
    def compute_shared_secret(self, private_key: bytes, public_key: bytes) -> bytes:
        """Perform X25519 ECDH to compute a shared secret."""
        return compute_shared_secret(private_key, public_key)

    # Serialization Utilities
    def serialize_key_pair(self, key_pair: KeyPair) -> SerializedKeyPair:
        """Serialize a key pair to base64-encoded strings."""
        return serialize_key_pair(key_pair)

    def deserialize_key_pair(self, serialized: SerializedKeyPair) -> KeyPair:
        """Deserialize a base64-encoded key pair."""
        return deserialize_key_pair(serialized)


# V1 API instance
v1 = V1API()

__all__ = ["v1", "V1API"]
