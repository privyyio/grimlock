/**
 * Version Manager for Grimlock crypto module
 * 
 * Central version registry that tracks available versions, provides version
 * metadata, and manages version compatibility.
 */

import type { VersionMetadata, CryptoConstants } from './types/version';
import { CRYPTO_CONSTANTS_V1 } from './versions/v1/constants';

/**
 * Version manager singleton
 */
class VersionManager {
  private versions: Map<string, VersionMetadata>;
  private latestVersion: string;

  constructor() {
    this.versions = new Map();
    this.latestVersion = 'v1';

    // Register v1
    this.registerVersion({
      version: 'v1',
      algorithms: {
        keyExchange: 'X25519',
        keyDerivation: 'Argon2id-v1',
        encryption: 'AES-256-GCM',
        hkdf: 'HKDF-SHA512',
      },
      constants: CRYPTO_CONSTANTS_V1,
      deprecated: false,
    });
  }

  /**
   * Register a new version
   */
  registerVersion(metadata: VersionMetadata): void {
    this.versions.set(metadata.version, metadata);

    // Update latest version if this is newer
    if (this.isNewerVersion(metadata.version, this.latestVersion)) {
      this.latestVersion = metadata.version;
    }
  }

  /**
   * Get the latest version string
   */
  getLatestVersion(): string {
    return this.latestVersion;
  }

  /**
   * Get version metadata
   */
  getVersion(version: string): VersionMetadata | undefined {
    return this.versions.get(version);
  }

  /**
   * Get all registered versions
   */
  getAllVersions(): VersionMetadata[] {
    return Array.from(this.versions.values());
  }

  /**
   * Check if two versions are compatible
   * For now, all versions are compatible (can decrypt each other's data)
   * This may change in the future if breaking changes are introduced
   */
  isCompatible(version1: string, version2: string): boolean {
    const v1 = this.versions.get(version1);
    const v2 = this.versions.get(version2);

    if (!v1 || !v2) {
      return false;
    }

    // For now, all versions are compatible
    // Future: implement compatibility matrix based on algorithm changes
    return true;
  }

  /**
   * Check if a version is deprecated
   */
  isDeprecated(version: string): boolean {
    const metadata = this.versions.get(version);
    return metadata?.deprecated ?? false;
  }

  /**
   * Simple version comparison (assumes semantic versioning: v1, v2, etc.)
   */
  private isNewerVersion(version1: string, version2: string): boolean {
    const v1Num = parseInt(version1.replace('v', ''), 10);
    const v2Num = parseInt(version2.replace('v', ''), 10);
    return v1Num > v2Num;
  }
}

// Singleton instance
let versionManagerInstance: VersionManager | null = null;

/**
 * Get the version manager instance
 */
export function getVersionManager(): VersionManager {
  if (!versionManagerInstance) {
    versionManagerInstance = new VersionManager();
  }
  return versionManagerInstance;
}

/**
 * Reset version manager (mainly for testing)
 */
export function resetVersionManager(): void {
  versionManagerInstance = null;
}
