"""X25519 key pair generation for Grimlock crypto module."""

import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from ...types.common import KeyPair
from ...types.v1 import KeyPairV1, new_key_pair_v1
from .constants import CRYPTO_CONSTANTS_V1


def generate_key_pair() -> KeyPairV1:
    """Generate a new X25519 key pair.

    Returns:
        KeyPairV1: A new key pair with version tag

    Raises:
        ValueError: If key generation fails
    """
    # Generate random private key
    private_key_bytes = os.urandom(CRYPTO_CONSTANTS_V1.x25519_key_size)

    # Create private key object
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)

    # Derive public key from private key
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return new_key_pair_v1(private_key_bytes, public_key_bytes)


def validate_key_pair(key_pair: KeyPair) -> None:
    """Validate that a key pair is well-formed.

    Args:
        key_pair: The key pair to validate

    Raises:
        ValueError: If the key pair is invalid
    """
    if len(key_pair.private_key) != CRYPTO_CONSTANTS_V1.x25519_key_size:
        raise ValueError(
            f"invalid private key size: expected {CRYPTO_CONSTANTS_V1.x25519_key_size}, "
            f"got {len(key_pair.private_key)}"
        )

    if len(key_pair.public_key) != CRYPTO_CONSTANTS_V1.x25519_key_size:
        raise ValueError(
            f"invalid public key size: expected {CRYPTO_CONSTANTS_V1.x25519_key_size}, "
            f"got {len(key_pair.public_key)}"
        )

    # Verify that public key matches private key
    try:
        private_key = x25519.X25519PrivateKey.from_private_bytes(key_pair.private_key)
        derived_public_key = private_key.public_key()
        derived_public_key_bytes = derived_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Constant-time comparison
        if not _bytes_equal(derived_public_key_bytes, key_pair.public_key):
            raise ValueError("public key does not match private key")
    except Exception as e:
        raise ValueError(f"failed to derive public key for validation: {e}") from e


def _bytes_equal(a: bytes, b: bytes) -> bool:
    """Perform constant-time comparison of byte slices."""
    if len(a) != len(b):
        return False

    result = 0
    for i in range(len(a)):
        result |= a[i] ^ b[i]

    return result == 0
