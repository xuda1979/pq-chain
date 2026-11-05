package state

import (
	"errors"
	"fmt"
	"time"

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

// MaxFutureBlockTime is how far a block timestamp may sit in the future
// relative to the verifying node's clock. Blocks further ahead are
// rejected so a faulty clock on one proposer cannot push the chain's
// median time forward unboundedly.
//
// DEPLOYMENT REQUIREMENT (consensus-critical): this check compares
// against each node's LOCAL wall clock. Two honest validators whose
// clocks differ by more than MaxFutureBlockTime can disagree about a
// block near the boundary — a consensus fork. Validator hosts MUST run
// NTP (or equivalent) with skew far below MaxFutureBlockTime. A fully
// deterministic alternative (Bitcoin-style median-time-past) is the
// production migration path if untrusted validator time ever becomes
// acceptable to constrain this way.
const MaxFutureBlockTime = 2 * time.Minute

// nowFunc is the clock seam. Tests override it to pin the wall clock;
// production code must never touch it.
var nowFunc = time.Now

// VerifyTransaction checks a transaction's signature against the
// sender's registered on-chain key using only OPEN-SOURCE verification.
// It also implements the two account-lifecycle rules:
//
//   - Enrollment (first registration): the sender has no key yet, so the
//     payload must carry a self-certifying key — one whose derived address
//     equals the sender address. The signature must verify under that
//     payload key, proving ownership.
//   - Key rotation: the sender IS registered, and the transaction rotates
//     the key (TxRegisterKey with a payload). The signature must verify
//     under the OLD registered key — rotation is authorized by the
//     incumbent — and SignBytes commits to the new key and scheme, so a
//     rotation signature cannot be replayed as anything else.
//
// Ordinary transactions from registered senders verify under the
// registered key as usual.
func VerifyTransaction(s *State, reg *crypto.Registry, tx *protocol.Transaction) error {
	from, ok := s.Accounts[tx.Sender]
	if !ok {
		return ErrUnknownAccount
	}
	if !from.Registered() {
		// Enrollment path: only key registration is allowed, and the
		// payload key must derive to the sender address (self-certifying).
		if tx.Kind != protocol.TxRegisterKey {
			return fmt.Errorf("state: sender %x has no registered key", tx.Sender[:4])
		}
		return verifyEnrollment(s, reg, tx)
	}
	// Registered sender: the signature must verify under the OLD
	// registered key. For TxRegisterKey that authorizes rotation: the tx
	// may carry a DIFFERENT scheme and key in Payload (the migration path
	// when a scheme is broken), and SignBytes commits to the new key and
	// scheme, so the incumbent's signature cannot be replayed elsewhere.
	// For all other kinds the tx scheme must match the registered one.
	if tx.Kind != protocol.TxRegisterKey && tx.SigScheme != from.SigScheme {
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

// ErrKeyMismatch is returned when a registration payload key does not
// derive to the sender address (enrollment) or the signature scheme does
// not match the payload key (rotation).
var ErrKeyMismatch = errors.New("state: key does not match sender address")

// verifyEnrollment validates the first registration of a sender: the
// payload must be a well-formed public key for the declared scheme whose
// address equals the sender, and the signature must verify under it.
func verifyEnrollment(s *State, reg *crypto.Registry, tx *protocol.Transaction) error {
	if err := crypto.ValidatePublicKey(tx.SigScheme, crypto.PublicKey(tx.Payload)); err != nil {
		return fmt.Errorf("state: enrollment key: %w", err)
	}
	addr, err := crypto.DeriveAddress(tx.SigScheme, crypto.PublicKey(tx.Payload))
	if err != nil {
		return err
	}
	if addr != tx.Sender {
		return ErrKeyMismatch
	}
	v, err := reg.Verifier(tx.SigScheme)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if err := v.Verify(crypto.PublicKey(tx.Payload), tx.SignBytes(), tx.Signature); err != nil {
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
//  5. the timestamp is sane: strictly after the parent's, bounded drift
//  6. the proposer is a staked account and the header carries a valid
//     proposer signature (open verification) over SignBytes
//  7. every transaction has a valid signature (open verification) and
//     applies cleanly to the evolving state
//  8. fees flow to the proposer, without overflowing anyone's balance
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
	// Block size limit first, before any O(n) work: an oversized block
	// must be rejected without hashing or verifying a single transaction.
	// Without this, a staked proposer could cheaply force every node into
	// unbounded verification time per block (resource-exhaustion vector).
	if len(block.Transactions) > protocol.MaxBlockTransactions {
		return nil, fmt.Errorf("state: block has %d transactions, limit %d",
			len(block.Transactions), protocol.MaxBlockTransactions)
	}
	if root := block.ComputeTxRoot(); !root.Equal(block.Header.TxRoot) {
		return nil, fmt.Errorf("state: tx root mismatch at height %d", block.Header.Height)
	}
	if err := parent.checkTimestamp(&block.Header); err != nil {
		return nil, err
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
	next.LastBlockTime = block.Header.Timestamp
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

// checkTimestamp enforces the chain clock: child timestamps must be
// strictly greater than the parent's (monotonic time, so light-client
// proofs and expiry logic cannot be attacked with time travel) and must
// not exceed the verifying node's wall clock by more than
// MaxFutureBlockTime (so a broken proposer clock cannot advance the
// chain's notion of "now" without bound). The parent's LastBlockTime of 0
// means "no previous block", which skips the monotonic check (genesis
// edge).
func (s *State) checkTimestamp(h *protocol.BlockHeader) error {
	if s.LastBlockTime != 0 && h.Timestamp <= s.LastBlockTime {
		return fmt.Errorf("state: block timestamp %d not after parent %d",
			h.Timestamp, s.LastBlockTime)
	}
	now := uint64(nowFunc().UnixMilli())
	if h.Timestamp > now+uint64(MaxFutureBlockTime/time.Millisecond) {
		return fmt.Errorf("state: block timestamp %d too far in the future", h.Timestamp)
	}
	return nil
}
