"""V1-specific type definitions for Grimlock crypto module."""

from typing import Literal

from .common import EncryptedMessage, EncryptedPrivateKey, KeyPair


class KeyPairV1(KeyPair):
    """V1 key pair with version tag."""

    _version: Literal["v1"] = "v1"


class EncryptedMessageV1(EncryptedMessage):
    """V1 encrypted message with version tag."""

    _version: Literal["v1"] = "v1"


class EncryptedPrivateKeyV1(EncryptedPrivateKey):
    """V1 encrypted private key with version tag."""

    _version: Literal["v1"] = "v1"


def new_key_pair_v1(private_key: bytes, public_key: bytes) -> KeyPairV1:
    """Create a new v1 key pair with version tag."""
    return KeyPairV1(private_key=private_key, public_key=public_key)


def new_encrypted_private_key_v1(
    iv: bytes, tag: bytes, ciphertext: bytes
) -> EncryptedPrivateKeyV1:
    """Create a new v1 encrypted private key with version tag."""
    return EncryptedPrivateKeyV1(iv=iv, tag=tag, ciphertext=ciphertext)


def new_encrypted_message_v1(
    eph_pub_key: bytes, iv: bytes, tag: bytes, ciphertext: bytes
) -> EncryptedMessageV1:
    """Create a new v1 encrypted message with version tag."""
    return EncryptedMessageV1(
        ephemeral_public_key=eph_pub_key,
        iv=iv,
        tag=tag,
        ciphertext=ciphertext,
    )
