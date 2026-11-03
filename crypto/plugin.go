package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// PluginManifest describes an optional accelerated crypto plugin. The
// manifest travels next to the plugin binary and is signed by the vendor
// release key. Loading is strictly opt-in: without a plugin, nodes use the
// open-source reference implementations for everything.
type PluginManifest struct {
	// Name is a human-readable plugin name.
	Name string `json:"name"`
	// Version is the plugin version string.
	Version string `json:"version"`
	// Vendor identifies the publisher.
	Vendor string `json:"vendor"`
	// Schemes lists the on-chain signature schemes the plugin accelerates.
	Schemes []string `json:"schemes"`
	// Binary is the plugin file name relative to the manifest.
	Binary string `json:"binary"`
	// SHA256 is the hex-encoded SHA-256 of the binary, for integrity.
	SHA256 string `json:"sha256"`
}

// ErrPluginNotFound is returned when a manifest or binary is missing.
var ErrPluginNotFound = errors.New("crypto: plugin not found")

// LoadPluginManifest reads and validates a plugin manifest (manifest.json)
// from dir. It does not load code; it only parses metadata.
func LoadPluginManifest(dir string) (*PluginManifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPluginNotFound, err)
	}
	var m PluginManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("crypto: bad plugin manifest: %w", err)
	}
	if m.Name == "" || m.Binary == "" {
		return nil, fmt.Errorf("crypto: plugin manifest missing name/binary")
	}
	return &m, nil
}
