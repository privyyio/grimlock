"""Common type definitions shared across all Grimlock crypto module versions."""

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class KeyPair:
    """Key pair structure (32 bytes each for X25519)."""

    private_key: bytes  # 32 bytes
    public_key: bytes  # 32 bytes


@dataclass
class SerializedKeyPair:
    """Serialized key pair for storage/transmission."""

    private_key: str  # Base64 encoded
    public_key: str  # Base64 encoded


@dataclass
class Argon2Params:
    """KDF (Key Derivation Function) parameters for Argon2id."""

    time_cost: int  # 4 (iterations)
    memory_cost: int  # 128 * 1024 (128MB in KB)
    parallelism: int  # 2


@dataclass
class KdfParams:
    """Complete KDF parameters including salt."""

    salt: bytes  # 32 bytes (256-bit)
    argon2_params: Argon2Params
    server_pepper: Optional[str] = None  # Optional server-side pepper for HMAC


@dataclass
class EncryptedPrivateKey:
    """Encrypted private key structure."""

    ciphertext: bytes
    iv: bytes  # 12 bytes (AES-GCM nonce)
    tag: bytes  # 16 bytes (AES-GCM auth tag)


@dataclass
class MessagePayload:
    """Message payload to be encrypted."""

    user_message: str
    assistant_response: str
    context: Optional[Dict[str, Any]] = None  # Optional context data


@dataclass
class MessageContext:
    """Context for message encryption/decryption."""

    conversation_id: str
    message_id: str


@dataclass
class EncryptedMessage:
    """Encrypted message structure."""

    ephemeral_public_key: bytes  # 32 bytes (X25519)
    iv: bytes  # 12 bytes
    tag: bytes  # 16 bytes
    ciphertext: bytes


@dataclass
class RecoveryKey:
    """Recovery key structure."""

    raw: bytes  # 32 bytes
    base64: str  # Base64 encoded (44 characters)
    mnemonic: Optional[str] = None  # Optional BIP39 mnemonic (24 words)
