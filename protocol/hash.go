package protocol

import (
	"crypto/sha256"
	"crypto/subtle"
)

// Hash is a 32-byte chain hash (transaction, block, account root, ...).
type Hash [HashSize]byte

// ZeroHash is the all-zero hash, used as the parent of the genesis block.
var ZeroHash Hash

// HashBytes computes the canonical hash of b using SHA-256.
// SHA-256 is itself considered quantum-resistant (Grover gives only a
// quadratic speedup); the signature layer above it is what must be
// post-quantum.
func HashBytes(b []byte) Hash {
	return Hash(sha256.Sum256(b))
}

// IsZero reports whether h is the all-zero hash.
func (h Hash) IsZero() bool { return h == ZeroHash }

// Bytes returns the hash as a byte slice.
func (h Hash) Bytes() []byte { return h[:] }

// Equal compares two hashes in constant time.
func (h Hash) Equal(other Hash) bool {
	return subtle.ConstantTimeCompare(h[:], other[:]) == 1
}

// Address is a 32-byte account identifier derived from a public key.
type Address [AddressSize]byte

// Bytes returns the address as a byte slice.
func (a Address) Bytes() []byte { return a[:] }
