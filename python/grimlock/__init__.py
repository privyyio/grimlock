"""Grimlock Crypto Module - Main Entry Point

This module provides versioned cryptographic operations for privyy.io.

Usage:
```python
# Default export (latest version)
import grimlock
key_pair = grimlock.generate_key_pair()

# Explicit version
from grimlock.versions import v1
key_pair = v1.generate_key_pair()

# Version manager
from grimlock import get_version_manager
manager = get_version_manager()
latest = manager.get_latest_version()  # "v1"
```
"""

from typing import Optional

from .version_manager import get_version_manager
from .versions import v1

# Export version namespaces
__all__ = ["v1", "get_version_manager", "detect_version", "requires_migration", "get_version_for_data"]

# Default export is the latest version (v1 for now)
# When v2 is implemented and becomes the latest, update this
default = v1

# Export default API methods for convenience
generate_key_pair = default.generate_key_pair
derive_passcode_key = default.derive_passcode_key
derive_recovery_key = default.derive_recovery_key
encrypt_private_key = default.encrypt_private_key
decrypt_private_key = default.decrypt_private_key
encrypt_message = default.encrypt_message
decrypt_message = default.decrypt_message
generate_recovery_key = default.generate_recovery_key
compute_shared_secret = default.compute_shared_secret
generate_salt = default.generate_salt
generate_default_kdf_params = default.generate_default_kdf_params


def detect_version(data: dict) -> Optional[str]:
    """Detect version from encrypted data structure.

    Checks for version markers in the data structure to determine
    which version was used to encrypt it.

    Args:
        data: Encrypted data structure (dict)

    Returns:
        Optional[str]: Version string or None if cannot be determined
    """
    # Check for explicit version field
    if isinstance(data, dict) and "_version" in data:
        version = data["_version"]
        if isinstance(version, str):
            return version

    # Check for version in metadata
    if isinstance(data, dict) and "metadata" in data:
        metadata = data["metadata"]
        if isinstance(metadata, dict) and "version" in metadata:
            version = metadata["version"]
            if isinstance(version, str):
                return version

    # Default to v1 if no version marker found
    # (for backward compatibility with data encrypted before versioning)
    return "v1"


def requires_migration(data: dict, target_version: str) -> bool:
    """Check if data needs migration to a newer version.

    Args:
        data: Encrypted data structure
        target_version: Target version to migrate to

    Returns:
        bool: True if migration is needed, false otherwise
    """
    current_version = detect_version(data)
    if not current_version:
        return False  # Cannot determine, assume no migration needed

    manager = get_version_manager()
    latest = manager.get_latest_version()

    # Only migrate if target is newer than current
    return target_version == latest and current_version != latest


def get_version_for_data(data: dict):
    """Get the appropriate API version for decrypting data.

    Args:
        data: Encrypted data structure

    Returns:
        V1API: Version-specific API (v1, v2, etc.)
    """
    version = detect_version(data) or "v1"

    if version == "v1":
        return v1
    # elif version == "v2":
    #     return v2
    else:
        # Default to v1 for unknown versions
        return v1
