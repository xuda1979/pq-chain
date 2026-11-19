package state

import (
	"errors"
	"testing"

	"github.com/xuda1979/pq-chain/crypto"
	"github.com/xuda1979/pq-chain/protocol"
)

// FuzzApplyTransactionArbitraryTx checks that the state machine never
// panics on arbitrary field combinations — every failure must be a
// consensus-visible error, never a panic.
func FuzzApplyTransactionArbitraryTx(f *testing.F) {
	f.Add(uint64(5), uint8(1), uint64(100), uint64(1000), uint64(0), false)
	f.Add(uint64(0), uint8(2), uint64(MinStake), uint64(BaseFee), uint64(9), true)
	f.Fuzz(func(t *testing.T, nonce uint64, kind uint8, amount, fee, toSeed uint64, hasAccount bool) {
		s := New()
		sender := protocol.Address{1}
		if hasAccount {
			s.Accounts[sender] = &Account{Balance: 10_000 * MinStake}
		}
		var to protocol.Address
		to[0] = byte(toSeed)
		to[1] = byte(toSeed >> 8)
		tx := &protocol.Transaction{
			Sender:  sender,
			Nonce:   nonce,
			Kind:    kind,
			To:      to,
			Amount:  amount,
			Fee:     fee,
			Payload: []byte{1, 2, 3},
		}
		_, err := s.ApplyTransaction(tx)
		if err == nil {
			return
		}
		// Rejections must be the documented consensus errors.
		switch {
		case errors.Is(err, ErrFeeTooLow),
			errors.Is(err, ErrUnknownAccount),
			errors.Is(err, ErrInvalidNonce),
			errors.Is(err, ErrInsufficientBalance),
			errors.Is(err, ErrZeroAmount),
			errors.Is(err, ErrStakeTooLow),
			errors.Is(err, ErrInsufficientStake),
			errors.Is(err, ErrUnstakePending),
			errors.Is(err, ErrUnknownTxKind),
			errors.Is(err, ErrEmptyKey),
			errors.Is(err, ErrKeyTooLarge),
			errors.Is(err, crypto.ErrInvalidKey),
			errors.Is(err, crypto.ErrUnsupportedScheme):
		default:
			t.Fatalf("unexpected error type: %v", err)
		}
	})
}

// FuzzApplyBlockShape applies arbitrarily-shaped but correctly signed
// blocks to a real parent state. It must never panic; nooks and crannies
// (bad heights, versions, fee/amount combos) are exercised freely. The
// tx signature is real, so the fuzz engine steers semantic values.
func FuzzApplyBlockShape(f *testing.F) {
	f.Add(uint64(2), uint8(1), uint64(5000), uint64(1000), uint64(1), uint64(0))
	f.Fuzz(func(t *testing.T, height uint64, kind uint8, amount, fee, version uint64, ts uint64) {
		if height > 3 {
			height = 2
		}
		if version > 2 {
			version = 1
		}
		s, reg, suite, _, sk := newTestChain(t)
		sender := senderAddr(t, s)
		proposer, proposerSK := newStakedProposer(t, s, suite)

		parentHeader := &protocol.BlockHeader{Version: 1, Height: 1, Proposer: proposer}
		s.LastBlockHash = parentHeader.Hash()
		s.Height = 1

		tx := &protocol.Transaction{
			Sender:    sender,
			Nonce:     0,
			Kind:      kind,
			To:        protocol.Address{9},
			Amount:    amount,
			Fee:       fee,
			Payload:   []byte{1, 2, 3},
			SigScheme: protocol.SchemeMLDSA65,
		}
		sig, err := suite.Sign(sk, tx.SignBytes())
		if err != nil {
			t.Fatal(err)
		}
		tx.Signature = sig

		block := &protocol.Block{
			Header: protocol.BlockHeader{
				Version:   uint32(version),
				Height:    height,
				Timestamp: ts,
				PrevHash:  parentHeader.Hash(),
				Proposer:  proposer,
			},
			Transactions: []*protocol.Transaction{tx},
		}
		block.Header.TxRoot = block.ComputeTxRoot()
		signBlock(t, suite, proposerSK, &block.Header)

		next, err := ApplyBlock(s, reg, block)
		if err != nil {
			return
		}
		// Supply invariant: value only moved, never printed.
		if next.TotalSupply() > s.TotalSupply() {
			t.Fatalf("supply inflated: %d -> %d", s.TotalSupply(), next.TotalSupply())
		}
	})
}
