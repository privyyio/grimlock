"""Key derivation functions for Grimlock crypto module.

Implements:
- Argon2id for passcode key derivation
- HKDF-SHA512 for shared secret and recovery key derivation
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ...types.common import KdfParams
from .constants import CRYPTO_CONSTANTS_V1


def derive_passcode_key(passcode: str, params: KdfParams) -> bytes:
    """Derive encryption key from passcode using Argon2id.

    Args:
        passcode: User's passcode (string)
        params: KDF parameters including salt and Argon2 params

    Returns:
        bytes: Derived encryption key (32 bytes)

    Raises:
        ValueError: If parameters are invalid
    """
    if not params.salt:
        raise ValueError("salt cannot be empty")
    if not passcode:
        raise ValueError("passcode cannot be empty")

    # Use provided parameters or defaults
    time_cost = params.argon2_params.time_cost
    memory_cost = params.argon2_params.memory_cost
    parallelism = params.argon2_params.parallelism

    if time_cost == 0:
        time_cost = CRYPTO_CONSTANTS_V1.argon2_time_cost
    if memory_cost == 0:
        memory_cost = CRYPTO_CONSTANTS_V1.argon2_memory_cost
    if parallelism == 0:
        parallelism = CRYPTO_CONSTANTS_V1.argon2_parallelism

    # Derive key using Argon2id
    # Use the low-level API to get raw bytes
    from argon2.low_level import Type, hash_secret_raw

    key = hash_secret_raw(
        secret=passcode.encode("utf-8"),
        salt=params.salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=CRYPTO_CONSTANTS_V1.aes_key_size,
        type=Type.ID,
    )

    return key


def derive_recovery_key(recovery_key_bytes: bytes) -> bytes:
    """Derive encryption key from recovery key bytes using HKDF-SHA512.

    Args:
        recovery_key_bytes: Raw recovery key bytes (32 bytes)

    Returns:
        bytes: Derived encryption key (32 bytes)

    Raises:
        ValueError: If recovery key size is invalid
    """
    if len(recovery_key_bytes) != CRYPTO_CONSTANTS_V1.recovery_key_size:
        raise ValueError(
            f"invalid recovery key size: expected {CRYPTO_CONSTANTS_V1.recovery_key_size}, "
            f"got {len(recovery_key_bytes)}"
        )

    # Use HKDF-SHA512 to derive encryption key from recovery key
    salt = CRYPTO_CONSTANTS_V1.hkdf_salt_recovery.encode("utf-8")
    info = CRYPTO_CONSTANTS_V1.hkdf_info_recovery.encode("utf-8")

    return _derive_key_hkdf(
        recovery_key_bytes, salt, info, CRYPTO_CONSTANTS_V1.aes_key_size
    )


def derive_message_key(shared_secret: bytes, context: str) -> bytes:
    """Derive message encryption key from ECDH shared secret using HKDF-SHA512.

    Args:
        shared_secret: ECDH shared secret (32 bytes)
        context: Context string in format "conversationId||messageId"

    Returns:
        bytes: Derived message key (32 bytes)

    Raises:
        ValueError: If shared secret size is invalid
    """
    if len(shared_secret) != 32:
        raise ValueError(f"invalid shared secret size: expected 32, got {len(shared_secret)}")

    # Use HKDF-SHA512 to derive message encryption key
    # Match Go format: "grimlock-message-key" + context
    salt = CRYPTO_CONSTANTS_V1.hkdf_salt_encryption.encode("utf-8")
    info = (CRYPTO_CONSTANTS_V1.hkdf_info_message + context).encode("utf-8")

    return _derive_key_hkdf(
        shared_secret, salt, info, CRYPTO_CONSTANTS_V1.aes_key_size
    )


def _derive_key_hkdf(ikm: bytes, salt: bytes, info: bytes, key_len: int) -> bytes:
    """Perform HKDF-SHA512 key derivation.

    Args:
        ikm: Input key material
        salt: Salt bytes
        info: Info bytes
        key_len: Desired key length

    Returns:
        bytes: Derived key
    """
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=key_len,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def generate_salt() -> bytes:
    """Generate a random salt for key derivation.

    Returns:
        bytes: Random salt (32 bytes)

    Raises:
        ValueError: If salt generation fails
    """
    salt = os.urandom(CRYPTO_CONSTANTS_V1.argon2_salt_size)
    return salt


def generate_default_kdf_params() -> KdfParams:
    """Generate default KDF parameters with a new random salt.

    Returns:
        KdfParams: Default KDF parameters with random salt
    """
    from ...types.common import Argon2Params

    salt = generate_salt()
    return KdfParams(
        salt=salt,
        argon2_params=Argon2Params(
            time_cost=CRYPTO_CONSTANTS_V1.argon2_time_cost,
            memory_cost=CRYPTO_CONSTANTS_V1.argon2_memory_cost,
            parallelism=CRYPTO_CONSTANTS_V1.argon2_parallelism,
        ),
    )
