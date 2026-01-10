"""Serialization utilities for Grimlock crypto module."""

import json
from typing import Dict

from .encoding import decode_base64, encode_base64

from ..types.common import (
    EncryptedMessage,
    EncryptedPrivateKey,
    KeyPair,
    SerializedKeyPair,
)


def serialize_key_pair(key_pair: KeyPair) -> SerializedKeyPair:
    """Serialize a key pair to base64-encoded strings."""
    return SerializedKeyPair(
        private_key=encode_base64(key_pair.private_key),
        public_key=encode_base64(key_pair.public_key),
    )


def deserialize_key_pair(serialized: SerializedKeyPair) -> KeyPair:
    """Deserialize a base64-encoded key pair."""
    private_key = decode_base64(serialized.private_key)
    public_key = decode_base64(serialized.public_key)
    return KeyPair(private_key=private_key, public_key=public_key)


def serialize_encrypted_private_key(encrypted: EncryptedPrivateKey) -> bytes:
    """Serialize an encrypted private key to JSON."""
    serialized: Dict[str, str] = {
        "iv": encode_base64(encrypted.iv),
        "tag": encode_base64(encrypted.tag),
        "ciphertext": encode_base64(encrypted.ciphertext),
    }
    return json.dumps(serialized).encode("utf-8")


def deserialize_encrypted_private_key(data: bytes) -> EncryptedPrivateKey:
    """Deserialize an encrypted private key from JSON."""
    try:
        serialized: Dict[str, str] = json.loads(data.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"failed to unmarshal encrypted private key: {e}") from e

    iv = decode_base64(serialized["iv"])
    tag = decode_base64(serialized["tag"])
    ciphertext = decode_base64(serialized["ciphertext"])

    return EncryptedPrivateKey(iv=iv, tag=tag, ciphertext=ciphertext)


def serialize_encrypted_message(encrypted: EncryptedMessage) -> bytes:
    """Serialize an encrypted message to JSON."""
    serialized: Dict[str, str] = {
        "ephemeralPublicKey": encode_base64(encrypted.ephemeral_public_key),
        "iv": encode_base64(encrypted.iv),
        "tag": encode_base64(encrypted.tag),
        "ciphertext": encode_base64(encrypted.ciphertext),
    }
    return json.dumps(serialized).encode("utf-8")


def deserialize_encrypted_message(data: bytes) -> EncryptedMessage:
    """Deserialize an encrypted message from JSON."""
    try:
        serialized: Dict[str, str] = json.loads(data.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"failed to unmarshal encrypted message: {e}") from e

    eph_pub_key = decode_base64(serialized["ephemeralPublicKey"])
    iv = decode_base64(serialized["iv"])
    tag = decode_base64(serialized["tag"])
    ciphertext = decode_base64(serialized["ciphertext"])

    return EncryptedMessage(
        ephemeral_public_key=eph_pub_key,
        iv=iv,
        tag=tag,
        ciphertext=ciphertext,
    )
