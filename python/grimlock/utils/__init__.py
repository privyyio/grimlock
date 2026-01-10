"""Utility functions for Grimlock crypto module."""

from .encoding import decode_base64, encode_base64
from .memory_security import secure_erase, secure_erase_multiple
from .serialization import (
    deserialize_encrypted_message,
    deserialize_encrypted_private_key,
    deserialize_key_pair,
    serialize_encrypted_message,
    serialize_encrypted_private_key,
    serialize_key_pair,
)

__all__ = [
    "encode_base64",
    "decode_base64",
    "secure_erase",
    "secure_erase_multiple",
    "serialize_key_pair",
    "deserialize_key_pair",
    "serialize_encrypted_private_key",
    "deserialize_encrypted_private_key",
    "serialize_encrypted_message",
    "deserialize_encrypted_message",
]
