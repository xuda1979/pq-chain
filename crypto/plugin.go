package crypto

import (
	"encoding/hex"
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

// ErrBadManifest is returned when a manifest is malformed or references
// files outside the plugin directory.
var ErrBadManifest = errors.New("crypto: bad plugin manifest")

// LoadPluginManifest reads and validates a plugin manifest (manifest.json)
// from dir. It does not load code; it only parses metadata.
func LoadPluginManifest(dir string) (*PluginManifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPluginNotFound, err)
	}
	var m PluginManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadManifest, err)
	}
	if m.Name == "" || m.Binary == "" {
		return nil, fmt.Errorf("%w: missing name/binary", ErrBadManifest)
	}
	// The manifest names the binary relative to the plugin dir; reject
	// anything that escapes it (absolute paths, "..", separators).
	if filepath.IsAbs(m.Binary) || m.Binary != filepath.Clean(filepath.Base(m.Binary)) {
		return nil, fmt.Errorf("%w: binary %q must be a plain file name", ErrBadManifest, m.Binary)
	}
	if len(m.SHA256) != 64 {
		return nil, fmt.Errorf("%w: sha256 must be 64 hex chars", ErrBadManifest)
	}
	if _, err := hex.DecodeString(m.SHA256); err != nil {
		return nil, fmt.Errorf("%w: sha256 is not hex: %w", ErrBadManifest, err)
	}
	return &m, nil
}
