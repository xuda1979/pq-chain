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
// It refuses allocations that would overflow the total supply.
func NewGenesis(alloc []Allocation) (*State, error) {
	s := New()
	var total uint64
	for _, a := range alloc {
		if a.Amount > ^uint64(0)-total {
			return nil, fmt.Errorf("state: genesis allocation overflows supply at %x", a.Address[:])
		}
		total += a.Amount
		acc := s.get(a.Address)
		if a.Amount > ^uint64(0)-acc.Balance {
			return nil, fmt.Errorf("state: duplicate genesis allocation for %x", a.Address[:])
		}
		acc.Balance += a.Amount
	}
	s.Height = 1
	return s, nil
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

// BlockVersion is the only block format version accepted at this height.
const BlockVersion = 1

// ApplyBlock validates a block against the parent state and returns the
// child state. Checks (all consensus-critical, all open):
//
//  1. header version == BlockVersion
//  2. height = parent height + 1
//  3. PrevHash = parent LastBlockHash
//  4. TxRoot matches the recomputed Merkle root
//  5. the proposer is a staked account and the header carries a valid
//     proposer signature (open verification) over SignBytes
//  6. every transaction has a valid signature (open verification) and
//     applies cleanly to the evolving state
//  7. fees flow to the proposer, without overflowing anyone's balance
//
// On any failure the parent state is untouched.
func ApplyBlock(parent *State, reg *crypto.Registry, block *protocol.Block) (*State, error) {
	if block.Header.Version != BlockVersion {
		return nil, fmt.Errorf("state: block version %d, want %d",
			block.Header.Version, BlockVersion)
	}
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

	// The proposer must be a registered, staked account, and the header
	// must carry the proposer's signature. Without this, anyone could
	// forge a fee-collecting header.
	proposerAcc, ok := parent.Accounts[block.Header.Proposer]
	if !ok {
		return nil, fmt.Errorf("state: unknown proposer at height %d", block.Header.Height)
	}
	if !proposerAcc.Registered() {
		return nil, fmt.Errorf("state: proposer %x has no registered key", block.Header.Proposer[:4])
	}
	if proposerAcc.Staked < MinStake {
		return nil, fmt.Errorf("state: proposer stake %d below minimum", proposerAcc.Staked)
	}
	if err := verifyHeader(parent, reg, &block.Header); err != nil {
		return nil, fmt.Errorf("state: proposer signature: %w", err)
	}

	// Single clone for the whole block: transactions apply to a working
	// copy and only the final result is published.
	next := parent.Clone()
	var fees uint64
	for i, tx := range block.Transactions {
		if err := VerifyTransaction(next, reg, tx); err != nil {
			return nil, fmt.Errorf("state: tx %d: %w", i, err)
		}
		if err := next.applyTx(tx); err != nil {
			return nil, fmt.Errorf("state: tx %d: %w", i, err)
		}
		if tx.Fee > ^uint64(0)-fees {
			return nil, fmt.Errorf("state: fee total overflow at tx %d", i)
		}
		fees += tx.Fee
	}

	// Fee routing: the proposer collects all transaction fees.
	if err := next.get(block.Header.Proposer).credit(fees); err != nil {
		return nil, fmt.Errorf("state: proposer credit: %w", err)
	}

	next.Height = block.Header.Height
	next.LastBlockHash = block.Header.Hash()
	next.SettleUnbondings()
	return next, nil
}

// verifyHeader checks the proposer's header signature against the
// proposer's registered on-chain key using only open-source verification.
func verifyHeader(parent *State, reg *crypto.Registry, h *protocol.BlockHeader) error {
	acc, ok := parent.Accounts[h.Proposer]
	if !ok || !acc.Registered() {
		return fmt.Errorf("proposer %x not registered", h.Proposer[:4])
	}
	v, err := reg.Verifier(acc.SigScheme)
	if err != nil {
		return err
	}
	if err := v.Verify(crypto.PublicKey(acc.PubKey), h.SignBytes(), h.ProposerSig); err != nil {
		return fmt.Errorf("header signature rejected: %w", err)
	}
	return nil
}
