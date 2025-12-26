/**
 * Grimlock Crypto Module - Main Entry Point
 * 
 * This module provides versioned cryptographic operations for privyy.io.
 * 
 * Usage:
 * ```typescript
 * // Default export (latest version)
 * import grimlock from '@/lib/crypto';
 * await grimlock.generateKeyPair();
 * 
 * // Explicit version
 * import { v1, v2 } from '@/lib/crypto';
 * await v1.generateKeyPair();
 * 
 * // Version manager
 * import { getVersionManager } from '@/lib/crypto';
 * const manager = getVersionManager();
 * const latest = manager.getLatestVersion(); // "v1"
 * ```
 */

import { v1 } from './versions/v1';
import { getVersionManager } from './version-manager';
import { GrimLock } from './types/v1';

// Export version namespaces
export { v1 };

// Export version manager
export { getVersionManager };

// Default export is the latest version (v1 for now)
// When v2 is implemented and becomes the latest, update this
const latest = v1;

export default latest;

/**
 * Version detection utilities
 */

/**
 * Detect version from encrypted data structure
 * 
 * Checks for version markers in the data structure to determine
 * which version was used to encrypt it.
 * 
 * @param data - Encrypted data structure
 * @returns Version string or null if cannot be determined
 */
export function detectVersion(data: unknown): string | null {
  // Check for explicit version field
  if (
    typeof data === 'object' &&
    data !== null &&
    '_version' in data &&
    typeof (data as { _version: string })._version === 'string'
  ) {
    return (data as { _version: string })._version;
  }

  // Check for version in metadata
  if (
    typeof data === 'object' &&
    data !== null &&
    'metadata' in data &&
    typeof (data as { metadata: unknown }).metadata === 'object' &&
    (data as { metadata: { version?: string } }).metadata !== null &&
    'version' in (data as { metadata: { version?: string } }).metadata
  ) {
    const version = (
      data as { metadata: { version: string } }
    ).metadata.version;
    if (typeof version === 'string') {
      return version;
    }
  }

  // Default to v1 if no version marker found
  // (for backward compatibility with data encrypted before versioning)
  return 'v1';
}

/**
 * Check if data needs migration to a newer version
 * 
 * @param data - Encrypted data structure
 * @param targetVersion - Target version to migrate to
 * @returns True if migration is needed, false otherwise
 */
export function requiresMigration(
  data: unknown,
  targetVersion: string
): boolean {
  const currentVersion = detectVersion(data);
  if (!currentVersion) {
    return false; // Cannot determine, assume no migration needed
  }

  const manager = getVersionManager();
  const latest = manager.getLatestVersion();

  // Only migrate if target is newer than current
  return targetVersion === latest && currentVersion !== latest;
}

/**
 * Get the appropriate API version for decrypting data
 * 
 * @param data - Encrypted data structure
 * @returns Version-specific API (v1, v2, etc.)
 */
export function getVersionForData(data: unknown): GrimLock {
  const version = detectVersion(data) || 'v1';

  switch (version) {
    case 'v1':
      return v1;
    // case 'v2':
    //   return v2;
    default:
      // Default to v1 for unknown versions
      return v1;
  }
}
