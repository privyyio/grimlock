package grimlock

import (
	"fmt"
	"sync"

	"github.com/privyy/grimlock/types"
	v1 "github.com/privyy/grimlock/v1"
)

// VersionManager manages crypto version metadata and routing
type VersionManager struct {
	versions      map[string]*types.VersionMetadata
	latestVersion string
	compatibility types.CompatibilityMatrix
	mu            sync.RWMutex
}

var (
	instance *VersionManager
	once     sync.Once
)

// GetVersionManager returns the singleton version manager instance
func GetVersionManager() *VersionManager {
	once.Do(func() {
		instance = &VersionManager{
			versions:      make(map[string]*types.VersionMetadata),
			latestVersion: "v1",
			compatibility: make(types.CompatibilityMatrix),
		}
		instance.registerVersions()
	})
	return instance
}

// registerVersions registers all available versions
func (vm *VersionManager) registerVersions() {
	// Register v1
	vm.versions["v1"] = &types.VersionMetadata{
		Version: "v1",
		Algorithms: types.AlgorithmVersions{
			KeyExchange:   "X25519",
			KeyDerivation: "Argon2id-v13",
			Encryption:    "AES-256-GCM",
			HKDF:          "HKDF-SHA512",
			RecoveryKey:   "256-bit-random",
			Serialization: "Base64",
		},
		Constants:  v1.Constants,
		Deprecated: false,
	}

	// Set up compatibility matrix
	vm.compatibility["v1"] = map[string]bool{
		"v1": true,
		// v1 can read v1 data
	}

	// Future versions can be registered here
	// vm.versions["v2"] = &types.VersionMetadata{...}
}

// GetLatestVersion returns the latest version string
func (vm *VersionManager) GetLatestVersion() string {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.latestVersion
}

// GetVersion returns metadata for a specific version
func (vm *VersionManager) GetVersion(version string) (*types.VersionMetadata, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	metadata, exists := vm.versions[version]
	if !exists {
		return nil, fmt.Errorf("version %s not found", version)
	}

	return metadata, nil
}

// IsCompatible checks if two versions are compatible
func (vm *VersionManager) IsCompatible(version1, version2 string) bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	compat, exists := vm.compatibility[version1]
	if !exists {
		return false
	}

	return compat[version2]
}

// ListVersions returns all registered version strings
func (vm *VersionManager) ListVersions() []string {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	versions := make([]string, 0, len(vm.versions))
	for v := range vm.versions {
		versions = append(versions, v)
	}
	return versions
}

// IsDeprecated checks if a version is deprecated
func (vm *VersionManager) IsDeprecated(version string) (bool, error) {
	metadata, err := vm.GetVersion(version)
	if err != nil {
		return false, err
	}
	return metadata.Deprecated, nil
}

// GetMigrationGuide returns the migration guide for a version
func (vm *VersionManager) GetMigrationGuide(version string) (string, error) {
	metadata, err := vm.GetVersion(version)
	if err != nil {
		return "", err
	}
	return metadata.MigrationGuide, nil
}
