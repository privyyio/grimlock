"""V1 Cryptographic Constants for Grimlock crypto module.

All constant strings use "grimlock" prefix instead of "okara"
"""

from ...types.version import CryptoConstants

# V1 cryptographic constants
CRYPTO_CONSTANTS_V1 = CryptoConstants(
    # X25519
    x25519_key_size=32,
    # Argon2id
    argon2_time_cost=4,
    argon2_memory_cost=128 * 1024,  # 128MB in KB
    argon2_parallelism=2,
    argon2_salt_size=32,
    # AES-GCM
    aes_key_size=32,  # 256 bits
    aes_iv_size=12,  # 96 bits (AES-GCM standard)
    aes_tag_size=16,  # 128 bits
    # HKDF
    hkdf_salt_encryption="grimlock-encryption-salt",
    hkdf_salt_recovery="grimlock-recovery-salt",
    hkdf_info_message="grimlock-message-key",
    hkdf_info_recovery="grimlock-recovery-key-derivation",
    hkdf_info_dual_encryption="grimlock-dual-encryption",
    hkdf_output_length=32,
    # Recovery Key
    recovery_key_size=32,  # 256 bits
    # Default pepper
    default_pepper="grimlock-default-pepper",
)
