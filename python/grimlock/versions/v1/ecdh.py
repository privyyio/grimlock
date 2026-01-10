"""X25519 ECDH operations for Grimlock crypto module."""

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from .constants import CRYPTO_CONSTANTS_V1


def compute_shared_secret(private_key: bytes, public_key: bytes) -> bytes:
    """Perform X25519 ECDH to compute a shared secret.

    Args:
        private_key: Private key bytes (32 bytes)
        public_key: Public key bytes (32 bytes)

    Returns:
        bytes: Shared secret (32 bytes)

    Raises:
        ValueError: If keys are invalid or computation fails
    """
    if len(private_key) != CRYPTO_CONSTANTS_V1.x25519_key_size:
        raise ValueError(
            f"invalid private key size: expected {CRYPTO_CONSTANTS_V1.x25519_key_size}, "
            f"got {len(private_key)}"
        )

    if len(public_key) != CRYPTO_CONSTANTS_V1.x25519_key_size:
        raise ValueError(
            f"invalid public key size: expected {CRYPTO_CONSTANTS_V1.x25519_key_size}, "
            f"got {len(public_key)}"
        )

    try:
        # Create private key object
        private_key_obj = x25519.X25519PrivateKey.from_private_bytes(private_key)

        # Create public key object
        public_key_obj = x25519.X25519PublicKey.from_public_bytes(public_key)

        # Compute shared secret
        shared_secret = private_key_obj.exchange(public_key_obj)

        return shared_secret
    except Exception as e:
        raise ValueError(f"ECDH computation failed: {e}") from e
