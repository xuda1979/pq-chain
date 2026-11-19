package store

import (
	"testing"

	"github.com/xuda1979/pq-chain/crypto"
	"github.com/xuda1979/pq-chain/protocol"
	"github.com/xuda1979/pq-chain/state"
)

// buildSignedChain constructs a small signed chain of n blocks starting
// from genesis, appends each to a fresh store, and returns the store plus
// the genesis state.
func buildSignedChain(t *testing.T, dir string, n uint64) (*Store, *state.State) {
	t.Helper()
	suite := crypto.NewMLDSA65()
	reg := crypto.NewRegistry()
	if err := reg.Register(suite); err != nil {
		t.Fatal(err)
	}
	// Genesis with two funded, registered accounts: proposer + payer.
	proposerPK, proposerSK, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	proposerAddr, err := crypto.DeriveAddress(protocol.SchemeMLDSA65, proposerPK)
	if err != nil {
		t.Fatal(err)
	}
	payerPK, payerSK, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payerAddr, err := crypto.DeriveAddress(protocol.SchemeMLDSA65, payerPK)
	if err != nil {
		t.Fatal(err)
	}
	gen := state.New()
	gen.Accounts[proposerAddr] = &state.Account{
		Balance:  100_000_000_000,
		Staked:   state.MinStake,
		PubKey:   append([]byte(nil), proposerPK...),
		SigScheme: protocol.SchemeMLDSA65,
	}
	gen.Accounts[payerAddr] = &state.Account{
		Balance:  1_000_000_000,
		PubKey:   append([]byte(nil), payerPK...),
		SigScheme: protocol.SchemeMLDSA65,
	}
	gen.Height = 1
	gen.LastBlockHash = protocol.ZeroHash

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Persist a genesis block (height 1, empty) so the journal is a
	// contiguous stream starting at 1. Replay starts applying at 2 because
	// `gen` is the state this genesis block already produced.
	genHdr := protocol.BlockHeader{
		Version:  state.BlockVersion,
		Height:   1,
		TxRoot:   protocol.ZeroHash,
		PrevHash: protocol.ZeroHash,
	}
	gsig, err := suite.Sign(proposerSK, genHdr.SignBytes())
	if err != nil {
		t.Fatal(err)
	}
	genHdr.ProposerSig = gsig
	if err := s.Append(&protocol.Block{Header: genHdr}); err != nil {
		t.Fatal(err)
	}

	cur := gen
	for h := uint64(2); h <= n+1; h++ {
		// One transfer from payer to proposer-address per block.
		tx := &protocol.Transaction{
			Sender:    payerAddr,
			Nonce:     h - 2,
			Kind:      protocol.TxTransfer,
			To:        proposerAddr,
			Amount:    100,
			Fee:       state.BaseFee,
			SigScheme: protocol.SchemeMLDSA65,
		}
		// compute SignBytes with tx fields
		sig, err := suite.Sign(payerSK, tx.SignBytes())
		if err != nil {
			t.Fatal(err)
		}
		tx.Signature = sig

		hdr := protocol.BlockHeader{
			Version:    state.BlockVersion,
			Height:     h,
			Timestamp:  gen.LastBlockTime + 6000 + h,
			PrevHash:   cur.LastBlockHash,
			TxRoot:     (&protocol.Block{Transactions: []*protocol.Transaction{tx}}).ComputeTxRoot(),
			Proposer:   proposerAddr,
		}
		hsig, err := suite.Sign(proposerSK, hdr.SignBytes())
		if err != nil {
			t.Fatal(err)
		}
		hdr.ProposerSig = hsig

		block := &protocol.Block{Header: hdr, Transactions: []*protocol.Transaction{tx}}
		next, err := state.ApplyBlock(cur, reg, block)
		if err != nil {
			t.Fatalf("apply block %d: %v", h, err)
		}
		if err := s.Append(block); err != nil {
			t.Fatalf("append block %d: %v", h, err)
		}
		cur = next
	}
	return s, gen
}

func TestStoreReplayRebuildsState(t *testing.T) {
	dir := t.TempDir()
	s, gen := buildSignedChain(t, dir, 5)
	last := s.Height()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	suite := crypto.NewMLDSA65()
	reg := crypto.NewRegistry()
	if err := reg.Register(suite); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	cur := gen
	for h := uint64(2); h <= last; h++ {
		b, err := s2.Get(h)
		if err != nil {
			t.Fatalf("get %d during replay: %v", h, err)
		}
		next, err := state.ApplyBlock(cur, reg, b)
		if err != nil {
			t.Fatalf("replay block %d: %v", h, err)
		}
		cur = next
	}
	// The payer should be drained by fees+amounts; total supply is closed
	// (fees stay inside the system, just move to the proposer).
	if cur.Height != last {
		t.Fatalf("replayed height %d, want %d", cur.Height, last)
	}
	// Proposer 100e9 balance + 1e9 stake, payer 1e9 = 102e9.
	if cur.TotalSupply() != 102_000_000_000 {
		t.Fatalf("supply closed: got %d, want 102e9", cur.TotalSupply())
	}
}
