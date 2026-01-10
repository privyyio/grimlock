"""Encoding utilities for Grimlock crypto module."""

import base64


def encode_base64(data: bytes) -> str:
    """Encode bytes to base64 string (standard encoding, not URL-safe)."""
    return base64.b64encode(data).decode("ascii")


def decode_base64(encoded: str) -> bytes:
    """Decode base64 string to bytes (standard encoding, not URL-safe)."""
    try:
        return base64.b64decode(encoded)
    except Exception as e:
        raise ValueError(f"failed to decode base64: {e}") from e
