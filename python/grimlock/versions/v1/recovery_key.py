"""Recovery key generation for Grimlock crypto module."""

import os
from mnemonic import Mnemonic

from ...types.common import RecoveryKey
from ...utils.encoding import encode_base64
from .constants import CRYPTO_CONSTANTS_V1
from .encryption import decrypt_private_key, encrypt_private_key
from .key_derivation import derive_recovery_key


def generate_recovery_key() -> RecoveryKey:
    """Generate a new cryptographically secure recovery key.

    Returns:
        RecoveryKey: Recovery key with raw bytes, base64 encoding, and optional mnemonic

    Raises:
        ValueError: If key generation fails
    """
    # Generate random 256-bit key
    key = os.urandom(CRYPTO_CONSTANTS_V1.recovery_key_size)

    # Generate BIP39 mnemonic (optional)
    try:
        mnemo = Mnemonic("english")
        mnemonic = mnemo.to_mnemonic(key)
    except Exception:
        # If mnemonic generation fails, continue without it
        mnemonic = None

    return RecoveryKey(
        raw=key,
        base64=encode_base64(key),
        mnemonic=mnemonic,
    )


def encrypt_private_key_with_recovery_key(
    private_key: bytes, recovery_key: bytes, aad: bytes
):
    """Encrypt a private key using a recovery key.

    Args:
        private_key: Private key to encrypt (32 bytes)
        recovery_key: Recovery key bytes (32 bytes)
        aad: Additional authenticated data

    Returns:
        EncryptedPrivateKeyV1: Encrypted private key

    Raises:
        ValueError: If recovery key size is invalid
    """
    if len(recovery_key) != CRYPTO_CONSTANTS_V1.recovery_key_size:
        raise ValueError(
            f"invalid recovery key size: expected {CRYPTO_CONSTANTS_V1.recovery_key_size}, "
            f"got {len(recovery_key)}"
        )

    # Derive encryption key from recovery key
    encryption_key = derive_recovery_key(recovery_key)

    try:
        # Encrypt private key
        return encrypt_private_key(private_key, encryption_key, aad)
    finally:
        # Best-effort secure erase
        if isinstance(encryption_key, bytearray):
            encryption_key[:] = b"\x00" * len(encryption_key)


def decrypt_private_key_with_recovery_key(
    encrypted, recovery_key: bytes, aad: bytes
) -> bytes:
    """Decrypt a private key using a recovery key.

    Args:
        encrypted: Encrypted private key
        recovery_key: Recovery key bytes (32 bytes)
        aad: Additional authenticated data

    Returns:
        bytes: Decrypted private key

    Raises:
        ValueError: If recovery key size is invalid
    """
    if len(recovery_key) != CRYPTO_CONSTANTS_V1.recovery_key_size:
        raise ValueError(
            f"invalid recovery key size: expected {CRYPTO_CONSTANTS_V1.recovery_key_size}, "
            f"got {len(recovery_key)}"
        )

    # Derive encryption key from recovery key
    encryption_key = derive_recovery_key(recovery_key)

    try:
        # Decrypt private key
        return decrypt_private_key(encrypted, encryption_key, aad)
    finally:
        # Best-effort secure erase
        if isinstance(encryption_key, bytearray):
            encryption_key[:] = b"\x00" * len(encryption_key)


def validate_recovery_key(recovery_key: bytes) -> None:
    """Validate that a recovery key is well-formed.

    Args:
        recovery_key: Recovery key bytes to validate

    Raises:
        ValueError: If recovery key is invalid
    """
    if len(recovery_key) != CRYPTO_CONSTANTS_V1.recovery_key_size:
        raise ValueError(
            f"invalid recovery key size: expected {CRYPTO_CONSTANTS_V1.recovery_key_size}, "
            f"got {len(recovery_key)}"
        )

    # Check that recovery key is not all zeros
    all_zero = all(b == 0 for b in recovery_key)
    if all_zero:
        raise ValueError("recovery key cannot be all zeros")
