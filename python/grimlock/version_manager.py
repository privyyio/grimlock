"""Version management utilities for Grimlock crypto module."""

from threading import Lock
from typing import Dict, Optional

from .types.version import (
    AlgorithmSpec,
    CompatibilityMatrix,
    CryptoConstants,
    VersionMetadata,
)
from .versions.v1.constants import CRYPTO_CONSTANTS_V1


class VersionManager:
    """Manages crypto version metadata and routing."""

    _instance: Optional["VersionManager"] = None
    _lock = Lock()

    def __init__(self):
        self._versions: Dict[str, VersionMetadata] = {}
        self._latest_version = "v1"
        self._compatibility: CompatibilityMatrix = {}
        self._register_versions()

    @classmethod
    def get_instance(cls) -> "VersionManager":
        """Get the singleton version manager instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _register_versions(self) -> None:
        """Register all available versions."""
        # Register v1
        self._versions["v1"] = VersionMetadata(
            version="v1",
            algorithms=AlgorithmSpec(
                key_exchange="X25519",
                key_derivation="Argon2id-v13",
                encryption="AES-256-GCM",
                hkdf="HKDF-SHA512",
            ),
            constants=CRYPTO_CONSTANTS_V1,
            deprecated=False,
        )

        # Set up compatibility matrix
        self._compatibility["v1"] = {"v1": True}

    def get_latest_version(self) -> str:
        """Get the latest version string."""
        return self._latest_version

    def get_version(self, version: str) -> VersionMetadata:
        """Get metadata for a specific version.

        Args:
            version: Version string (e.g., "v1")

        Returns:
            VersionMetadata: Version metadata

        Raises:
            ValueError: If version not found
        """
        metadata = self._versions.get(version)
        if metadata is None:
            raise ValueError(f"version {version} not found")
        return metadata

    def is_compatible(self, version1: str, version2: str) -> bool:
        """Check if two versions are compatible.

        Args:
            version1: First version string
            version2: Second version string

        Returns:
            bool: True if versions are compatible
        """
        compat = self._compatibility.get(version1)
        if compat is None:
            return False
        return compat.get(version2, False)

    def list_versions(self) -> list[str]:
        """List all registered version strings.

        Returns:
            list[str]: List of version strings
        """
        return list(self._versions.keys())

    def is_deprecated(self, version: str) -> bool:
        """Check if a version is deprecated.

        Args:
            version: Version string

        Returns:
            bool: True if version is deprecated

        Raises:
            ValueError: If version not found
        """
        metadata = self.get_version(version)
        return metadata.deprecated

    def get_migration_guide(self, version: str) -> Optional[str]:
        """Get the migration guide for a version.

        Args:
            version: Version string

        Returns:
            Optional[str]: Migration guide or None

        Raises:
            ValueError: If version not found
        """
        metadata = self.get_version(version)
        return metadata.migration_guide


def get_version_manager() -> VersionManager:
    """Get the singleton version manager instance."""
    return VersionManager.get_instance()
