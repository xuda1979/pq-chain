package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/your-org/pq-chain-public/plugin"
	"github.com/your-org/pq-chain-public/protocol"
)

// PluginSignatureFile is the detached signature over the plugin binary
// (SHA-256 over the binary, signed with the vendor Ed25519 release key).
const PluginSignatureFile = "binary.sig"

// ErrPluginIntegrity is returned when a plugin binary fails hash or
// signature verification. Loading untrusted native code into a node is a
// supply-chain risk, so this is deliberately strict.
var ErrPluginIntegrity = errors.New("crypto: plugin integrity check failed")

// VendorReleaseKey is the Ed25519 public key that signs official plugin
// binaries. In production this is distributed with the node software and
// rotated via on-chain governance. Replace before mainnet.
var VendorReleaseKey ed25519.PublicKey

// LoadAcceleratedSigner loads a vendor-signed accelerated signer plugin
// and returns its Signer handle plus a closer. It verifies:
//  1. the binary hash matches manifest.SHA256,
//  2. the detached Ed25519 signature over that hash,
//  3. the plugin handshake reports the expected ABI version and scheme.
//
// To close the TOCTOU gap between verification and execution, the exact
// verified bytes are copied to a private temporary file and executed from
// there — a concurrent swap of the original path cannot change what runs.
// It never loads unsigned plugins. Verify paths always stay in open-source
// code; plugins only accelerate signing.
func LoadAcceleratedSigner(dir string, wantScheme protocol.SignatureScheme) (Signer, func(), error) {
	manifest, err := LoadPluginManifest(dir)
	if err != nil {
		return nil, nil, err
	}
	binPath := filepath.Join(dir, manifest.Binary)
	bin, err := os.ReadFile(binPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPluginNotFound, err)
	}

	// 1. Hash check against manifest.
	sum := sha256.Sum256(bin)
	if manifest.SHA256 != hex.EncodeToString(sum[:]) {
		return nil, nil, fmt.Errorf("%w: binary hash mismatch", ErrPluginIntegrity)
	}

	// 2. Detached signature over the raw binary hash.
	if VendorReleaseKey == nil {
		return nil, nil, fmt.Errorf("%w: no vendor release key configured", ErrPluginIntegrity)
	}
	sig, err := os.ReadFile(filepath.Join(dir, PluginSignatureFile))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: missing %s", ErrPluginIntegrity, PluginSignatureFile)
	}
	if !ed25519.Verify(VendorReleaseKey, sum[:], sig) {
		return nil, nil, fmt.Errorf("%w: bad signature", ErrPluginIntegrity)
	}

	// 3. Execute exactly the verified bytes: stage a private temp copy
	// (0700, not in the plugin dir, which may be a read-only mount) and
	// run that. The copy is removed once the plugin has started — the
	// kernel keeps the inode alive for the running process — so a
	// concurrent swap of the original path cannot change what runs.
	staged, err := stageVerifiedBinary(bin)
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(staged)

	// 4. Handshake via the plugin protocol (stdout handshake line, then
	// JSON-RPC over a unix socket).
	client, err := plugin.Dial(staged)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: plugin dial: %w", err)
	}
	signer, err := NewPluginSigner(client, wantScheme)
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	return signer, func() { signer.Close() }, nil
}

// stageVerifiedBinary writes the verified plugin bytes to a fresh private
// executable file in the system temp dir and returns its path.
func stageVerifiedBinary(bin []byte) (string, error) {
	tmp, err := os.CreateTemp("", "pqc-plugin-verified-")
	if err != nil {
		return "", fmt.Errorf("crypto: stage verified plugin: %w", err)
	}
	path := tmp.Name()
	// Best-effort removal if anything below fails.
	ok := false
	defer func() {
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		return "", fmt.Errorf("crypto: stage verified plugin: %w", err)
	}
	if err := tmp.Chmod(0o700); err != nil {
		tmp.Close()
		return "", fmt.Errorf("crypto: stage verified plugin: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("crypto: stage verified plugin: %w", err)
	}
	ok = true
	return path, nil
}
