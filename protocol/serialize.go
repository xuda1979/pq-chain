// Package protocol defines the canonical data structures and serialization
// rules of the PQ chain. Everything in this package is consensus-critical:
// every node must serialize and hash these structures identically.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ChainID identifies the chain to prevent replay across networks.
const ChainID = "pq-chain-devnet-0"

// HashSize is the length of a chain hash (SHA3-256 / SHA-256).
const HashSize = 32

// AddressSize is the length of an account address (SHA3-256 of a public key).
const AddressSize = 32

// SignatureScheme identifies the signature algorithm a key pair uses.
// It is recorded on-chain so verifiers know which algorithm to dispatch to.
type SignatureScheme uint8

const (
	// SchemeMLDSA44 is ML-DSA-44 (FIPS 204, NIST security level 2).
	SchemeMLDSA44 SignatureScheme = 1
	// SchemeMLDSA65 is ML-DSA-65 (FIPS 204, NIST security level 3).
	SchemeMLDSA65 SignatureScheme = 2
	// SchemeMLDSA87 is ML-DSA-87 (FIPS 204, NIST security level 5).
	SchemeMLDSA87 SignatureScheme = 3
)

// String returns a human-readable name for the scheme.
func (s SignatureScheme) String() string {
	switch s {
	case SchemeMLDSA44:
		return "ML-DSA-44"
	case SchemeMLDSA65:
		return "ML-DSA-65"
	case SchemeMLDSA87:
		return "ML-DSA-87"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// PutUint64 appends v in canonical little-endian encoding.
func PutUint64(b []byte, v uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return append(b, buf[:]...)
}

// PutUint32 appends v in canonical little-endian encoding.
func PutUint32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

// PutBytes appends a length-prefixed byte string (uint32 LE length + bytes).
// Length prefixes make the encoding unambiguous, which is required for
// collision-free hashing.
func PutBytes(b []byte, v []byte) []byte {
	b = PutUint32(b, uint32(len(v)))
	return append(b, v...)
}

var (
	// ErrMalformed is returned when a serialized structure is truncated
	// or otherwise does not follow the canonical encoding rules.
	ErrMalformed = errors.New("protocol: malformed serialized data")

	// ErrTrailingBytes is returned when a buffer has unconsumed bytes left
	// after decoding a structure, which would make the encoding ambiguous.
	ErrTrailingBytes = errors.New("protocol: trailing bytes after structure")
)

// Reader consumes a canonical-encoded byte stream. All decoding is strict:
// truncated input, invalid lengths and trailing bytes are rejected so that
// every valid encoding is uniquely decodable.
type Reader struct {
	buf []byte
	off int
}

// NewReader returns a Reader over b.
func NewReader(b []byte) *Reader {
	return &Reader{buf: b}
}

// Remaining reports how many undecoded bytes are left.
func (r *Reader) Remaining() int { return len(r.buf) - r.off }

// Uint64 reads a canonical little-endian uint64.
func (r *Reader) Uint64() (uint64, error) {
	if r.Remaining() < 8 {
		return 0, ErrMalformed
	}
	v := binary.LittleEndian.Uint64(r.buf[r.off:])
	r.off += 8
	return v, nil
}

// Uint32 reads a canonical little-endian uint32.
func (r *Reader) Uint32() (uint32, error) {
	if r.Remaining() < 4 {
		return 0, ErrMalformed
	}
	v := binary.LittleEndian.Uint32(r.buf[r.off:])
	r.off += 4
	return v, nil
}

// Uint8 reads a single byte.
func (r *Reader) Uint8() (uint8, error) {
	if r.Remaining() < 1 {
		return 0, ErrMalformed
	}
	v := r.buf[r.off]
	r.off++
	return v, nil
}

// Bytes reads a length-prefixed byte string.
func (r *Reader) Bytes() ([]byte, error) {
	n, err := r.Uint32()
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(r.Remaining()) {
		return nil, ErrMalformed
	}
	v := make([]byte, n)
	copy(v, r.buf[r.off:r.off+int(n)])
	r.off += int(n)
	return v, nil
}

// Fixed reads exactly n raw bytes (no length prefix; the size is fixed by
// the protocol, e.g. hashes and addresses).
func (r *Reader) Fixed(n int) ([]byte, error) {
	if n < 0 || r.Remaining() < n {
		return nil, ErrMalformed
	}
	v := make([]byte, n)
	copy(v, r.buf[r.off:r.off+n])
	r.off += n
	return v, nil
}
