// Package crypto defines the public cryptography interfaces of the PQ chain
// and ships complete, open-source verification for all standardized
// algorithms. High-performance signing implementations may be provided by
// optional plugins, but every node can always verify without them.
package crypto

import (
	"crypto/sha256"
	"errors"

	"github.com/your-org/pq-chain-public/protocol"
)

// PublicKey is a raw encoded public key of a post-quantum signature scheme.
type PublicKey []byte

// PrivateKey is a raw encoded private key. Implementations must treat it
// as sensitive material.
type PrivateKey []byte

// Signature is a raw encoded signature.
type Signature []byte

// Signer is the plugin surface for signature generation. This interface is
// implemented in open source (reference implementation) and may also be
// implemented by closed-source accelerated plugins. Signing is the
// "generation side" and may be proprietary.
type Signer interface {
	// Scheme reports which on-chain signature scheme this signer produces.
	Scheme() protocol.SignatureScheme
	// GenerateKeyPair creates a new key pair.
	GenerateKeyPair() (PublicKey, PrivateKey, error)
	// Sign creates a signature over msg with sk.
	Sign(sk PrivateKey, msg []byte) (Signature, error)
}

// Verifier is the open-source verification surface. NOTE: verification is
// consensus-critical and must never depend on closed-source code.
type Verifier interface {
	// Scheme reports which on-chain signature scheme this verifier accepts.
	Scheme() protocol.SignatureScheme
	// Verify reports whether sig is a valid signature of msg under pk.
	Verify(pk PublicKey, msg, sig Signature) error
}

// FullSuite combines signing and verification for one scheme.
type FullSuite interface {
	Signer
	Verifier
}

var (
	// ErrInvalidSignature is returned when a signature fails verification.
	// Deliberately generic: callers must not learn WHY a forgery failed.
	ErrInvalidSignature = errors.New("crypto: invalid signature")

	// ErrUnsupportedScheme is returned when no suite is registered for a
	// scheme ID.
	ErrUnsupportedScheme = errors.New("crypto: unsupported signature scheme")

	// ErrInvalidKey is returned when a key is empty or malformed at the
	// interface boundary.
	ErrInvalidKey = errors.New("crypto: invalid key")
)

// Registry maps on-chain scheme IDs to implementations. Verification
// entries are used by every node; signing entries are only used by key
// holders.
type Registry struct {
	suites map[protocol.SignatureScheme]FullSuite
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{suites: make(map[protocol.SignatureScheme]FullSuite)}
}

// Register adds a suite for its scheme. A scheme can be registered only
// once; verification must be deterministic across the network.
func (r *Registry) Register(s FullSuite) error {
	if _, dup := r.suites[s.Scheme()]; dup {
		return errors.New("crypto: scheme already registered")
	}
	r.suites[s.Scheme()] = s
	return nil
}

// Signer returns the signing half for a scheme.
func (r *Registry) Signer(scheme protocol.SignatureScheme) (Signer, error) {
	suite, ok := r.suites[scheme]
	if !ok {
		return nil, ErrUnsupportedScheme
	}
	return suite, nil
}

// Verifier returns the verification half for a scheme.
func (r *Registry) Verifier(scheme protocol.SignatureScheme) (Verifier, error) {
	suite, ok := r.suites[scheme]
	if !ok {
		return nil, ErrUnsupportedScheme
	}
	return suite, nil
}

// Verify signs nothing and leaks nothing: a single entry point for
// consensus verification.
func (r *Registry) Verify(pk PublicKey, msg, sig Signature, scheme protocol.SignatureScheme) error {
	v, err := r.Verifier(scheme)
	if err != nil {
		return err
	}
	return v.Verify(pk, msg, sig)
}

// DeriveAddress computes the canonical account address for a public key:
// SHA-256 of scheme byte || raw public key. Addresses bind the key to a
// scheme so signatures cannot be replayed across algorithms.
func DeriveAddress(scheme protocol.SignatureScheme, pk PublicKey) (protocol.Address, error) {
	if len(pk) == 0 {
		return protocol.Address{}, ErrInvalidKey
	}
	h := sha256.New()
	h.Write([]byte{byte(scheme)})
	h.Write(pk)
	var addr protocol.Address
	copy(addr[:], h.Sum(nil))
	return addr, nil
}
