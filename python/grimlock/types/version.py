"""Version metadata types for Grimlock crypto module."""

from dataclasses import dataclass
from typing import Dict, Optional

from .common import Argon2Params


@dataclass
class CryptoConstants:
    """Cryptographic constants for a version."""

    # X25519
    x25519_key_size: int  # 32

    # Argon2id
    argon2_time_cost: int
    argon2_memory_cost: int
    argon2_parallelism: int
    argon2_salt_size: int  # 32

    # AES-GCM
    aes_key_size: int  # 32 (256 bits)
    aes_iv_size: int  # 12 (96 bits)
    aes_tag_size: int  # 16 (128 bits)

    # HKDF
    hkdf_salt_encryption: str  # 'grimlock-encryption-salt'
    hkdf_salt_recovery: str  # 'grimlock-recovery-salt'
    hkdf_info_message: str  # 'grimlock-message-key'
    hkdf_info_recovery: str  # 'grimlock-recovery-key-derivation'
    hkdf_info_dual_encryption: str  # 'grimlock-dual-encryption'
    hkdf_output_length: int  # 32

    # Recovery Key
    recovery_key_size: int  # 32 (256 bits)

    # Default pepper
    default_pepper: str  # 'grimlock-default-pepper'


@dataclass
class AlgorithmSpec:
    """Algorithm specifications for a version."""

    key_exchange: str  # "X25519"
    key_derivation: str  # "Argon2id-v1"
    encryption: str  # "AES-256-GCM"
    hkdf: str  # "HKDF-SHA512"


@dataclass
class VersionMetadata:
    """Version metadata."""

    version: str  # "v1", "v2", etc.
    algorithms: AlgorithmSpec
    constants: CryptoConstants
    deprecated: bool = False
    migration_guide: Optional[str] = None


# Compatibility matrix type
CompatibilityMatrix = Dict[str, Dict[str, bool]]
