package crypto

import (
	"crypto/mldsa"
	"crypto/sha3"
	"fmt"

	"github.com/your-org/pq-chain-public/protocol"
)

// MLDSASuite is the open-source reference implementation of ML-DSA
// (FIPS 204, Module-Lattice-Based Digital Signature Algorithm) for one
// parameter set. Both signing and verification live here: the reference
// signer is a complete fallback so the network never depends on
// closed-source code. Accelerated plugins replace only the Sign path.
type MLDSASuite struct {
	scheme  protocol.SignatureScheme
	params  mldsa.Parameters
}

// NewMLDSA44 returns the ML-DSA-44 suite (NIST level 2).
func NewMLDSA44() *MLDSASuite {
	return &MLDSASuite{scheme: protocol.SchemeMLDSA44, params: mldsa.MLDSA44()}
}

// NewMLDSA65 returns the ML-DSA-65 suite (NIST level 3).
func NewMLDSA65() *MLDSASuite {
	return &MLDSASuite{scheme: protocol.SchemeMLDSA65, params: mldsa.MLDSA65()}
}

// NewMLDSA87 returns the ML-DSA-87 suite (NIST level 5).
func NewMLDSA87() *MLDSASuite {
	return &MLDSASuite{scheme: protocol.SchemeMLDSA87, params: mldsa.MLDSA87()}
}

// Scheme implements Signer/Verifier.
func (s *MLDSASuite) Scheme() protocol.SignatureScheme { return s.scheme }

// paramsFor maps a scheme ID to its FIPS 204 parameter set.
func paramsFor(scheme protocol.SignatureScheme) (mldsa.Parameters, error) {
	switch scheme {
	case protocol.SchemeMLDSA44:
		return mldsa.MLDSA44(), nil
	case protocol.SchemeMLDSA65:
		return mldsa.MLDSA65(), nil
	case protocol.SchemeMLDSA87:
		return mldsa.MLDSA87(), nil
	default:
		return mldsa.Parameters{}, ErrUnsupportedScheme
	}
}

// GenerateKeyPair implements Signer. Keys are generated with the OS CSPRNG.
func (s *MLDSASuite) GenerateKeyPair() (PublicKey, PrivateKey, error) {
	priv, err := mldsa.GenerateKey(s.params)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: ML-DSA keygen: %w", err)
	}
	return PublicKey(priv.PublicKey().Bytes()), PrivateKey(priv.Bytes()), nil
}

// Sign implements Signer using the stdlib reference implementation.
func (s *MLDSASuite) Sign(sk PrivateKey, msg []byte) (Signature, error) {
	if len(sk) == 0 {
		return nil, ErrInvalidKey
	}
	priv, err := mldsa.NewPrivateKey(s.params, sk)
	if err != nil {
		return nil, fmt.Errorf("crypto: ML-DSA private key: %w", err)
	}
	return priv.Sign(nil, msg, nil)
}

// Verify implements Verifier. It is fully self-contained and open source:
// every node on the network runs this code (or a byte-compatible
// reimplementation) to validate every transaction and block.
func (s *MLDSASuite) Verify(pk PublicKey, msg, sig Signature) error {
	if len(pk) == 0 {
		return ErrInvalidKey
	}
	pub, err := mldsa.NewPublicKey(s.params, pk)
	if err != nil {
		return fmt.Errorf("%w: bad public key", ErrInvalidSignature)
	}
	return mldsa.Verify(pub, msg, sig, nil)
}

// PublicKeySize returns the raw public key size for a scheme (FIPS 204
// parameter-set constants). Consensus code uses it to reject keys that
// could never verify before they are committed to state.
func PublicKeySize(scheme protocol.SignatureScheme) (int, error) {
	switch scheme {
	case protocol.SchemeMLDSA44:
		return 1312, nil
	case protocol.SchemeMLDSA65:
		return 1952, nil
	case protocol.SchemeMLDSA87:
		return 2592, nil
	default:
		return 0, ErrUnsupportedScheme
	}
}

// ValidatePublicKey checks that pk is well-formed for scheme: correct size
// and parseable by the reference implementation. State transitions use it
// so an account can never register a key that would brick it (a malformed
// key makes every future signature check fail, which is unrecoverable).
func ValidatePublicKey(scheme protocol.SignatureScheme, pk PublicKey) error {
	params, err := paramsFor(scheme)
	if err != nil {
		return err
	}
	want, err := PublicKeySize(scheme)
	if err != nil {
		return err
	}
	if len(pk) != want {
		return fmt.Errorf("%w: public key size %d, want %d", ErrInvalidKey, len(pk), want)
	}
	if _, err := mldsa.NewPublicKey(params, pk); err != nil {
		return fmt.Errorf("%w: unparseable public key", ErrInvalidKey)
	}
	return nil
}

// KeyFingerprint gives a short human-checkable fingerprint of a public key,
// useful for display and auditing ("address ending" in UIs). Not part of
// consensus.
func KeyFingerprint(pk PublicKey) string {
	h := sha3.Sum256(pk)
	return fmt.Sprintf("%x", h[:8])
}
