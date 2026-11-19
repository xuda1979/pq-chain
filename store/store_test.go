package store

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/xuda1979/pq-chain/protocol"
)

// testBlock builds a minimal valid-height block without signature checks
// (store only validates continuity + serialization, not consensus).
func testBlock(height uint64) *protocol.Block {
	h := protocol.BlockHeader{Version: 1, Height: height, Timestamp: 1730000000000 + height}
	copy(h.PrevHash[:], []byte("prev hash bytes exactly 32 long!"))
	h.ProposerSig = []byte{0x01, 0x02, 0x03}
	b := &protocol.Block{Header: h}
	b.Transactions = []*protocol.Transaction{
		{Nonce: height, Kind: protocol.TxTransfer, Amount: 100, Fee: 5, SigScheme: protocol.SchemeMLDSA44},
	}
	b.Transactions[0].Signature = []byte{0xAB, 0xCD}
	return b
}

func TestAppendGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if !s.Empty() {
		t.Fatal("fresh store must be empty")
	}
	for h := uint64(1); h <= 5; h++ {
		if err := s.Append(testBlock(h)); err != nil {
			t.Fatalf("append %d: %v", h, err)
		}
	}
	if s.Height() != 5 {
		t.Fatalf("height %d, want 5", s.Height())
	}
	for h := uint64(1); h <= 5; h++ {
		got, err := s.Get(h)
		if err != nil {
			t.Fatalf("get %d: %v", h, err)
		}
		if got.Header.Height != h {
			t.Fatalf("height mismatch at %d", h)
		}
		if got.Header.Hash() != testBlock(h).Header.Hash() {
			t.Fatalf("block hash mismatch at %d", h)
		}
	}
	if _, err := s.Get(6); err != ErrOutOfRange {
		t.Fatalf("get beyond top: want ErrOutOfRange, got %v", err)
	}
	if _, err := s.Get(0); err != ErrOutOfRange {
		t.Fatalf("get 0: want ErrOutOfRange, got %v", err)
	}
}

func TestReopenPersistence(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for h := uint64(1); h <= 3; h++ {
		if err := s.Append(testBlock(h)); err != nil {
			t.Fatalf("append %d: %v", h, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if s2.Height() != 3 {
		t.Fatalf("reopened height %d, want 3", s2.Height())
	}
	got, err := s2.Get(2)
	if err != nil {
		t.Fatalf("reopened get 2: %v", err)
	}
	if got.Header.Hash() != testBlock(2).Header.Hash() {
		t.Fatal("reopened block mismatch")
	}
	// Append must continue at 4.
	if err := s2.Append(testBlock(4)); err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
}

func TestTornTailIsTruncated(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for h := uint64(1); h <= 3; h++ {
		if err := s.Append(testBlock(h)); err != nil {
			t.Fatalf("append %d: %v", h, err)
		}
	}
	// Simulate a crash mid-block-4-append: file has the length prefix and
	// a partial record. Reopen must truncate the tail and keep 1..3.
	file, err := os.OpenFile(filepath.Join(dir, "chain.journal"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open journal for corruption: %v", err)
	}
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], 700) // claims a block way bigger than the partial bytes
	file.Write(lenBuf[:])
	file.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF}) // partial block bytes
	file.Close()
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after tear: %v", err)
	}
	defer s2.Close()
	if s2.Height() != 3 {
		t.Fatalf("after tear: height %d, want 3", s2.Height())
	}
	if err := s2.Append(testBlock(4)); err != nil {
		t.Fatalf("append after tear: %v", err)
	}
}

func TestAppendRejectsGap(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if err := s.Append(testBlock(1)); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	if err := s.Append(testBlock(3)); err == nil {
		t.Fatal("append height 3 after 1 must be rejected (gap)")
	}
	if err := s.Append(testBlock(1)); err == nil {
		t.Fatal("append duplicate height must be rejected")
	}
}

func TestLockedByAnotherOpen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if _, err := Open(dir); err != ErrLocked {
		t.Fatalf("second open: want ErrLocked, got %v", err)
	}
}
