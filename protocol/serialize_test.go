package protocol

import (
	"bytes"
	"testing"
)

func TestTransactionRoundTrip(t *testing.T) {
	tx := &Transaction{
		Nonce:     7,
		Kind:      TxTransfer,
		Amount:    1000,
		Fee:       10,
		Payload:   []byte("stake-pubkey"),
		SigScheme: SchemeMLDSA65,
		Signature: bytes.Repeat([]byte{0xAB}, 3309),
	}
	copy(tx.Sender[:], []byte("sender-sender-sender-sender-32"))
	copy(tx.To[:], []byte("recipient-recipient-recipient!"))

	data := tx.Marshal()
	var got Transaction
	if err := got.Unmarshal(data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Hash() != tx.Hash() {
		t.Fatal("hash mismatch after round trip")
	}
	if !bytes.Equal(got.SignBytes(), tx.SignBytes()) {
		t.Fatal("sign bytes mismatch after round trip")
	}
}

func TestTransactionRejectsTrailingBytes(t *testing.T) {
	tx := &Transaction{Nonce: 1, Kind: TxTransfer, SigScheme: SchemeMLDSA44}
	data := append(tx.Marshal(), 0x00)
	var got Transaction
	if err := got.Unmarshal(data); err == nil {
		t.Fatal("expected error for trailing bytes")
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	h := &BlockHeader{
		Version:   1,
		Height:    42,
		Timestamp: 1730000000000,
		Proposer:  Address{1, 2, 3},
	}
	copy(h.PrevHash[:], []byte("prev hash bytes exactly 32 long!"))
	copy(h.TxRoot[:], []byte("tx root bytes exactly 32 long!!"))
	h.ProposerSig = bytes.Repeat([]byte{0xCD}, 4627)

	var got BlockHeader
	if err := got.Unmarshal(h.Marshal()); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Hash() != h.Hash() {
		t.Fatal("hash mismatch after round trip")
	}
	if !bytes.Equal(got.SignBytes(), h.SignBytes()) {
		t.Fatal("sign bytes mismatch after round trip")
	}
}

func TestComputeTxRoot(t *testing.T) {
	b := &Block{}
	if root := b.ComputeTxRoot(); !root.IsZero() {
		t.Fatal("empty block must have zero tx root")
	}

	b.Transactions = []*Transaction{
		{Nonce: 1, Kind: TxTransfer, Amount: 5},
		{Nonce: 2, Kind: TxTransfer, Amount: 6},
		{Nonce: 3, Kind: TxStake, Amount: 100},
	}
	root := b.ComputeTxRoot()
	if root.IsZero() {
		t.Fatal("non-empty block must have non-zero tx root")
	}

	// Reordering transactions must change the root.
	b.Transactions[0], b.Transactions[1] = b.Transactions[1], b.Transactions[0]
	if reordered := b.ComputeTxRoot(); reordered == root {
		t.Fatal("reordering transactions must change the tx root")
	}
}
