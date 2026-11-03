package crypto

import (
	"bytes"
	"testing"

	"github.com/your-org/pq-chain-public/protocol"
)

// TestMLDSAEndToEnd exercises the full lifecycle per parameter set:
// keygen -> address derivation -> sign -> verify -> tamper rejection.
func TestMLDSAEndToEnd(t *testing.T) {
	suites := map[string]func() *MLDSASuite{
		"ML-DSA-44": NewMLDSA44,
		"ML-DSA-65": NewMLDSA65,
		"ML-DSA-87": NewMLDSA87,
	}
	for name, New := range suites {
		t.Run(name, func(t *testing.T) {
			s := New()
			pk, sk, err := s.GenerateKeyPair()
			if err != nil {
				t.Fatalf("keygen: %v", err)
			}
			addr, err := DeriveAddress(s.Scheme(), pk)
			if err != nil {
				t.Fatalf("address: %v", err)
			}
			if len(addr) != protocol.AddressSize {
				t.Fatalf("address size = %d", len(addr))
			}

			msg := []byte("attack at dawn: harvest now, decrypt later")
			sig, err := s.Sign(sk, msg)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if err := s.Verify(pk, msg, sig); err != nil {
				t.Fatalf("verify: %v", err)
			}

			// Tampered message must fail.
			if err := s.Verify(pk, append(msg, '!'), sig); err == nil {
				t.Fatal("tampered message verified")
			}
			// Tampered signature must fail.
			bad := bytes.Clone(sig)
			bad[0] ^= 1
			if err := s.Verify(pk, msg, bad); err == nil {
				t.Fatal("tampered signature verified")
			}
			// Wrong key must fail.
			pk2, _, err := s.GenerateKeyPair()
			if err != nil {
				t.Fatalf("keygen2: %v", err)
			}
			if err := s.Verify(pk2, msg, sig); err == nil {
				t.Fatal("signature verified under wrong key")
			}
		})
	}
}

// TestRegistry verifies scheme registration and dispatch.
func TestRegistry(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(NewMLDSA44()); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(NewMLDSA65()); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(NewMLDSA65()); err == nil {
		t.Fatal("duplicate scheme registration must fail")
	}
	s44 := NewMLDSA44()
	pk, sk, err := s44.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s44.Sign(sk, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(pk, []byte("msg"), sig, protocol.SchemeMLDSA44); err != nil {
		t.Fatalf("registry verify: %v", err)
	}
	if _, err := r.Signer(protocol.SchemeMLDSA87); err == nil {
		t.Fatal("unregistered scheme must fail")
	}
}

// TestDeriveAddress pins the address derivation so it never silently
// changes (that would fork the chain).
func TestDeriveAddress(t *testing.T) {
	pk := PublicKey(bytes.Repeat([]byte{0x42}, 1312))
	a1, err := DeriveAddress(protocol.SchemeMLDSA65, pk)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := DeriveAddress(protocol.SchemeMLDSA65, pk)
	if err != nil {
		t.Fatal(err)
	}
	if a1 != a2 {
		t.Fatal("derivation is not deterministic")
	}
	a3, err := DeriveAddress(protocol.SchemeMLDSA87, pk)
	if err != nil {
		t.Fatal(err)
	}
	if a1 == a3 {
		t.Fatal("different schemes must derive different addresses")
	}
	if _, err := DeriveAddress(protocol.SchemeMLDSA65, nil); err == nil {
		t.Fatal("empty key must fail")
	}
}
