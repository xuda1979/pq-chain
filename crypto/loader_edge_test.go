package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/xuda1979/pq-chain/protocol"
)

// writePkg writes a minimal plugin package for loader tests.
func writePkg(t *testing.T, dir, binName string, bin []byte, sha string, sig []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, binName), bin, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"name":"test","version":"1","vendor":"T","schemes":["ML-DSA-65"],` +
		`"binary":"` + binName + `","sha256":"` + sha + `"}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if sig != nil {
		if err := os.WriteFile(filepath.Join(dir, PluginSignatureFile), sig, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func mustVendorKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// TestManifestRejectsPathTraversal pins the loader against manifests that
// point outside the plugin directory.
func TestManifestRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, bin := range []string{"../evil", "/etc/passwd", "sub/dir/evil", "..\\evil"} {
		m := `{"name":"x","binary":"` + bin + `","sha256":"` + hex.EncodeToString(make([]byte, 32)) + `"}`
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(m), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPluginManifest(dir); err == nil {
			t.Fatalf("manifest with binary %q accepted", bin)
		}
	}
}

// TestManifestRejectsBadHash pins manifest hash-format validation.
func TestManifestRejectsBadHash(t *testing.T) {
	dir := t.TempDir()
	for _, sha := range []string{"", "abcd", "zz"} {
		m := `{"name":"x","binary":"bin","sha256":"` + sha + `"}`
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(m), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPluginManifest(dir); err == nil {
			t.Fatalf("manifest with sha256 %q accepted", sha)
		}
	}
}

// TestLoaderRejectsTamperedBinary proves hash and signature enforcement
// end-to-end without needing a runnable plugin binary.
func TestLoaderRejectsTamperedBinary(t *testing.T) {
	vendorPub, vendorPriv := mustVendorKey(t)
	old := VendorReleaseKey
	VendorReleaseKey = vendorPub
	defer func() { VendorReleaseKey = old }()

	dir := t.TempDir()
	bin := []byte("fake plugin bytes")
	sum := sha256.Sum256(bin)
	sig := ed25519.Sign(vendorPriv, sum[:])

	// Correct hash but NO signature file.
	writePkg(t, dir, "p", bin, hex.EncodeToString(sum[:]), nil)
	if _, _, err := LoadAcceleratedSigner(dir, protocol.SchemeMLDSA65); err == nil {
		t.Fatal("missing signature accepted")
	}

	// Correct hash, signature over DIFFERENT data.
	badSig := ed25519.Sign(vendorPriv, []byte("other"))
	writePkg(t, dir, "p", bin, hex.EncodeToString(sum[:]), badSig)
	if _, _, err := LoadAcceleratedSigner(dir, protocol.SchemeMLDSA65); err == nil {
		t.Fatal("bad signature accepted")
	}

	// Mismatched hash.
	writePkg(t, dir, "p", append(bin, 'x'), hex.EncodeToString(sum[:]), sig)
	if _, _, err := LoadAcceleratedSigner(dir, protocol.SchemeMLDSA65); err == nil {
		t.Fatal("tampered binary accepted")
	}

	// No vendor key configured at all.
	saved := VendorReleaseKey
	VendorReleaseKey = nil
	writePkg(t, dir, "p", bin, hex.EncodeToString(sum[:]), sig)
	if _, _, err := LoadAcceleratedSigner(dir, protocol.SchemeMLDSA65); err == nil {
		t.Fatal("load accepted without vendor key")
	}
	VendorReleaseKey = saved
}
