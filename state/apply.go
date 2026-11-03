package state

import (
	"fmt"

	"github.com/your-org/pq-chain-public/crypto"
	"github.com/your-org/pq-chain-public/protocol"
)

// Allocation is one genesis allocation entry.
type Allocation struct {
	Address protocol.Address
	Amount  uint64
}

// GenesisAlloc is the set of devnet genesis allocations. Mainnet values
// come from the economics spec; the structure is consensus-critical.
var GenesisAlloc = []Allocation{}

// NewGenesis returns the state after the genesis block (height 1).
// Genesis carries no transactions; it only instantiates allocations.
func NewGenesis(alloc []Allocation) *State {
	s := New()
	for _, a := range alloc {
		acc := s.get(a.Address)
		acc.Balance = a.Amount
	}
	s.Height = 1
	return s
}

// VerifyTransaction checks a transaction's signature against the
// sender's registered on-chain key using only OPEN-SOURCE verification.
// Unregistered senders are rejected; this is the crypto↔state seam.
func VerifyTransaction(s *State, reg *crypto.Registry, tx *protocol.Transaction) error {
	from, ok := s.Accounts[tx.Sender]
	if !ok {
		return ErrUnknownAccount
	}
	if !from.Registered() {
		return fmt.Errorf("state: sender %x has no registered key", tx.Sender[:4])
	}
	// The signature scheme must match the registered key's scheme.
	if tx.SigScheme != from.SigScheme {
		return fmt.Errorf("state: tx scheme %s does not match registered %s",
			tx.SigScheme, from.SigScheme)
	}
	v, err := reg.Verifier(from.SigScheme)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if err := v.Verify(crypto.PublicKey(from.PubKey), tx.SignBytes(), tx.Signature); err != nil {
		return fmt.Errorf("state: signature rejected: %w", err)
	}
	return nil
}

// ApplyBlock validates a block against the parent state and returns the
// child state. Checks (all consensus-critical, all open):
//
//  1. height = parent height + 1
//  2. PrevHash = parent LastBlockHash
//  3. TxRoot matches the recomputed Merkle root
//  4. every transaction has a valid signature (open verification) and
//     applies cleanly to the evolving state
//  5. fees flow to the proposer
//
// On any failure the parent state is untouched.
func ApplyBlock(parent *State, reg *crypto.Registry, block *protocol.Block) (*State, error) {
	if block.Header.Height != parent.Height+1 {
		return nil, fmt.Errorf("state: block height %d, want %d",
			block.Header.Height, parent.Height+1)
	}
	if !block.Header.PrevHash.Equal(parent.LastBlockHash) {
		return nil, fmt.Errorf("state: prev hash mismatch at height %d", block.Header.Height)
	}
	if root := block.ComputeTxRoot(); !root.Equal(block.Header.TxRoot) {
		return nil, fmt.Errorf("state: tx root mismatch at height %d", block.Header.Height)
	}

	next := parent.Clone()
	var fees uint64
	for i, tx := range block.Transactions {
		if err := VerifyTransaction(next, reg, tx); err != nil {
			return nil, fmt.Errorf("state: tx %d: %w", i, err)
		}
		after, err := next.ApplyTransaction(tx)
		if err != nil {
			return nil, fmt.Errorf("state: tx %d: %w", i, err)
		}
		next = after
		fees += tx.Fee
	}

	// Fee routing: the proposer collects all transaction fees.
	proposer := next.get(block.Header.Proposer)
	proposer.Balance += fees

	next.Height = block.Header.Height
	next.LastBlockHash = block.Header.Hash()
	next.SettleUnbondings()
	return next, nil
}
