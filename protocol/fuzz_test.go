package protocol

import (
	"errors"
	"testing"
)

// FuzzTransactionDecode checks that Unmarshal never panics on arbitrary
// input, accepts every valid Marshal output, and is canonical: re-encoding
// what was decoded reproduces the original bytes.
func FuzzTransactionDecode(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0})
	f.Add([]byte{})
	tx := &Transaction{
		Nonce:     7,
		Kind:      TxTransfer,
		Amount:    1000,
		Fee:       10,
		Payload:   []byte("stake-pubkey"),
		SigScheme: SchemeMLDSA65,
		Signature: make([]byte, 3309),
	}
	copy(tx.Sender[:], []byte("sender-sender-sender-sender-32"))
	copy(tx.To[:], []byte("recipient-recipient-recipient!"))
	f.Add(tx.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		var got Transaction
		if err := got.Unmarshal(data); err != nil {
			// Rejections must be the documented error types.
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrTrailingBytes) && !errors.Is(err, ErrInvalidField) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		// Accepted input must round-trip byte-for-byte (canonical form).
		if enc := got.Marshal(); string(enc) != string(data) {
			t.Fatalf("non-canonical decode:\nin:  %x\nout: %x", data, enc)
		}
	})
}

// FuzzTransactionRoundTripStability is the simpler invariant: any
// constructed transaction must survive Marshal->Unmarshal->Marshal with
// identical bytes and identical SignBytes.
func FuzzTransactionRoundTripStability(f *testing.F) {
	f.Add(uint64(3), uint8(2), uint64(42), uint64(7), "payload", "sig", uint8(2))
	f.Add(uint64(0), uint8(1), uint64(0), uint64(0), "", "", uint8(1))
	f.Fuzz(func(t *testing.T, nonce uint64, kind uint8, amount, fee uint64, payload, sig string, scheme uint8) {
		if len(payload) > MaxPayloadSize || len(sig) > MaxSignatureSize {
			t.Skip()
		}
		// Only defined schemes can round-trip: Unmarshal rejects unknown
		// scheme IDs by design (consensus rule), so Marshal->Unmarshal is
		// only expected to succeed for valid ones.
		s := SignatureScheme(scheme)
		switch s {
		case SchemeMLDSA44, SchemeMLDSA65, SchemeMLDSA87:
		default:
			t.Skip()
		}
		tx := &Transaction{
			Nonce:     nonce,
			Kind:      kind,
			Amount:    amount,
			Fee:       fee,
			Payload:   []byte(payload),
			SigScheme: s,
			Signature: []byte(sig),
		}
		data := tx.Marshal()
		var back Transaction
		if err := back.Unmarshal(data); err != nil {
			t.Fatalf("decode of Marshal output failed: %v", err)
		}
		if string(back.Marshal()) != string(data) {
			t.Fatal("Marshal is not canonical")
		}
		if string(back.SignBytes()) != string(tx.SignBytes()) {
			t.Fatal("SignBytes changed across round trip")
		}
	})
}

// FuzzHeaderDecode checks header decoding against arbitrary input.
func FuzzHeaderDecode(f *testing.F) {
	f.Add([]byte{})
	h := &BlockHeader{Version: 1, Height: 42, Timestamp: 1730000000000}
	h.ProposerSig = make([]byte, 4627)
	f.Add(h.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		var got BlockHeader
		if err := got.Unmarshal(data); err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrTrailingBytes) && !errors.Is(err, ErrInvalidField) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if enc := got.Marshal(); string(enc) != string(data) {
			t.Fatalf("non-canonical decode:\nin:  %x\nout: %x", data, enc)
		}
	})
}
