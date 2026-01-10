"""AES-256-GCM encryption operations for Grimlock crypto module."""

import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ...types.common import EncryptedPrivateKey, MessageContext, MessagePayload
from ...types.v1 import EncryptedMessageV1, EncryptedPrivateKeyV1, new_encrypted_message_v1, new_encrypted_private_key_v1
from .constants import CRYPTO_CONSTANTS_V1


def encrypt_private_key(
    private_key: bytes, encryption_key: bytes, aad: bytes
) -> EncryptedPrivateKeyV1:
    """Encrypt a private key using AES-256-GCM.

    Args:
        private_key: Private key to encrypt (32 bytes)
        encryption_key: Encryption key (32 bytes)
        aad: Additional authenticated data

    Returns:
        EncryptedPrivateKeyV1: Encrypted private key with version tag

    Raises:
        ValueError: If key sizes are invalid
    """
    if len(private_key) != CRYPTO_CONSTANTS_V1.x25519_key_size:
        raise ValueError(
            f"invalid private key size: expected {CRYPTO_CONSTANTS_V1.x25519_key_size}, "
            f"got {len(private_key)}"
        )
    if len(encryption_key) != CRYPTO_CONSTANTS_V1.aes_key_size:
        raise ValueError(
            f"invalid encryption key size: expected {CRYPTO_CONSTANTS_V1.aes_key_size}, "
            f"got {len(encryption_key)}"
        )

    # Generate random IV
    iv = os.urandom(CRYPTO_CONSTANTS_V1.aes_iv_size)

    # Create AES-GCM cipher
    aesgcm = AESGCM(encryption_key)

    # Encrypt (Seal combines ciphertext and tag)
    ciphertext_with_tag = aesgcm.encrypt(iv, private_key, aad)

    # Split ciphertext and tag
    tag_start = len(ciphertext_with_tag) - CRYPTO_CONSTANTS_V1.aes_tag_size
    ciphertext = ciphertext_with_tag[:tag_start]
    tag = ciphertext_with_tag[tag_start:]

    return new_encrypted_private_key_v1(iv, tag, ciphertext)


def decrypt_private_key(
    encrypted: EncryptedPrivateKey, encryption_key: bytes, aad: bytes
) -> bytes:
    """Decrypt a private key using AES-256-GCM.

    Args:
        encrypted: Encrypted private key
        encryption_key: Encryption key (32 bytes)
        aad: Additional authenticated data

    Returns:
        bytes: Decrypted private key

    Raises:
        ValueError: If key sizes are invalid or decryption fails
    """
    if len(encryption_key) != CRYPTO_CONSTANTS_V1.aes_key_size:
        raise ValueError(
            f"invalid encryption key size: expected {CRYPTO_CONSTANTS_V1.aes_key_size}, "
            f"got {len(encryption_key)}"
        )
    if len(encrypted.iv) != CRYPTO_CONSTANTS_V1.aes_iv_size:
        raise ValueError(
            f"invalid IV size: expected {CRYPTO_CONSTANTS_V1.aes_iv_size}, "
            f"got {len(encrypted.iv)}"
        )
    if len(encrypted.tag) != CRYPTO_CONSTANTS_V1.aes_tag_size:
        raise ValueError(
            f"invalid tag size: expected {CRYPTO_CONSTANTS_V1.aes_tag_size}, "
            f"got {len(encrypted.tag)}"
        )

    # Create AES-GCM cipher
    aesgcm = AESGCM(encryption_key)

    # Combine ciphertext and tag for GCM Open
    ciphertext_with_tag = encrypted.ciphertext + encrypted.tag

    # Decrypt and verify
    try:
        plaintext = aesgcm.decrypt(encrypted.iv, ciphertext_with_tag, aad)
    except Exception as e:
        raise ValueError(
            "decryption failed (invalid key or tampered data)"
        ) from e

    return plaintext


def encrypt_message_payload(
    payload: MessagePayload, message_key: bytes, iv: bytes, aad: bytes
) -> tuple[bytes, bytes]:
    """Encrypt a message payload using AES-256-GCM.

    Args:
        payload: Message payload to encrypt
        message_key: Message encryption key (32 bytes)
        iv: Initialization vector (12 bytes)
        aad: Additional authenticated data

    Returns:
        tuple[bytes, bytes]: (ciphertext, tag)

    Raises:
        ValueError: If encryption fails
    """
    # Serialize payload to JSON
    payload_bytes = json.dumps(
        {
            "userMessage": payload.user_message,
            "assistantResponse": payload.assistant_response,
            "optionalContext": payload.context or {},
        }
    ).encode("utf-8")

    # Create AES-GCM cipher
    aesgcm = AESGCM(message_key)

    # Encrypt with AAD
    ciphertext_with_tag = aesgcm.encrypt(iv, payload_bytes, aad)

    # Split ciphertext and tag
    tag_start = len(ciphertext_with_tag) - CRYPTO_CONSTANTS_V1.aes_tag_size
    ciphertext = ciphertext_with_tag[:tag_start]
    tag = ciphertext_with_tag[tag_start:]

    return ciphertext, tag


def decrypt_message_payload(
    ciphertext: bytes, message_key: bytes, iv: bytes, tag: bytes, aad: bytes
) -> MessagePayload:
    """Decrypt a message payload using AES-256-GCM.

    Args:
        ciphertext: Encrypted ciphertext
        message_key: Message encryption key (32 bytes)
        iv: Initialization vector (12 bytes)
        tag: Authentication tag (16 bytes)
        aad: Additional authenticated data

    Returns:
        MessagePayload: Decrypted message payload

    Raises:
        ValueError: If decryption fails
    """
    # Create AES-GCM cipher
    aesgcm = AESGCM(message_key)

    # Combine ciphertext and tag for GCM Open
    ciphertext_with_tag = ciphertext + tag

    # Decrypt and verify
    try:
        payload_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, aad)
    except Exception as e:
        raise ValueError(
            "decryption failed (invalid key or tampered data)"
        ) from e

    # Deserialize payload from JSON
    try:
        payload_dict = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"failed to deserialize payload: {e}") from e

    return MessagePayload(
        user_message=payload_dict["userMessage"],
        assistant_response=payload_dict["assistantResponse"],
        context=payload_dict.get("optionalContext"),
    )


def create_metadata_aad(context: MessageContext) -> bytes:
    """Create metadata as AAD (additional authenticated data).

    Args:
        context: Message context

    Returns:
        bytes: AAD bytes in format "conversationId||messageId"
    """
    return f"{context.conversation_id}||{context.message_id}".encode("utf-8")
