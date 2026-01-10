"""Type definitions for Grimlock crypto module."""

from .common import (
    Argon2Params,
    EncryptedMessage,
    EncryptedPrivateKey,
    KeyPair,
    KdfParams,
    MessageContext,
    MessagePayload,
    RecoveryKey,
    SerializedKeyPair,
)
from .v1 import (
    EncryptedMessageV1,
    EncryptedPrivateKeyV1,
    KeyPairV1,
    new_encrypted_message_v1,
    new_encrypted_private_key_v1,
    new_key_pair_v1,
)

__all__ = [
    # Common types
    "KeyPair",
    "SerializedKeyPair",
    "KdfParams",
    "Argon2Params",
    "EncryptedPrivateKey",
    "MessagePayload",
    "MessageContext",
    "EncryptedMessage",
    "RecoveryKey",
    # V1 types
    "KeyPairV1",
    "EncryptedPrivateKeyV1",
    "EncryptedMessageV1",
    "new_key_pair_v1",
    "new_encrypted_private_key_v1",
    "new_encrypted_message_v1",
]
