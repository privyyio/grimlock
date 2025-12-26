package grimlock

import (
	"encoding/json"
	"fmt"
)

// DetectVersion attempts to detect the version from encrypted data
func DetectVersion(data interface{}) (string, error) {
	// Try to detect version tag in the data
	switch v := data.(type) {
	case map[string]interface{}:
		if version, ok := v["_version"].(string); ok {
			return version, nil
		}
	case []byte:
		// Try to unmarshal as JSON and check for version
		var m map[string]interface{}
		if err := json.Unmarshal(v, &m); err == nil {
			if version, ok := m["_version"].(string); ok {
				return version, nil
			}
		}
	}

	// Default to v1 if no version tag found (for backward compatibility)
	return "v1", nil
}

// RequiresMigration checks if data needs to be migrated to a target version
func RequiresMigration(data interface{}, targetVersion string) (bool, error) {
	currentVersion, err := DetectVersion(data)
	if err != nil {
		return false, err
	}

	// Check if versions are different
	if currentVersion != targetVersion {
		// Check if migration path exists
		manager := GetVersionManager()
		if !manager.IsCompatible(currentVersion, targetVersion) {
			return false, fmt.Errorf("no migration path from %s to %s", currentVersion, targetVersion)
		}
		return true, nil
	}

	return false, nil
}

// GetVersionForData returns the appropriate API version for the given data
func GetVersionForData(data interface{}) (string, error) {
	version, err := DetectVersion(data)
	if err != nil {
		return "", err
	}

	// Verify version exists
	manager := GetVersionManager()
	if _, err := manager.GetVersion(version); err != nil {
		return "", fmt.Errorf("unsupported version %s: %w", version, err)
	}

	return version, nil
}
