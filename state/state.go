// Package state implements the chain's account state and the state
// transition function. Everything here is consensus-critical and open:
// given the same parent state and the same block, every node must compute
// the identical result.
package state

import (
	"errors"
	"fmt"

	"github.com/your-org/pq-chain-public/protocol"
)

// Protocol constants (devnet values; final values set per economics spec).
const (
	// MinStake is the smallest stake that admits an account to the
	// validator set.
	MinStake uint64 = 1_000_000_000 // 1 PQ in nano-units

	// UnbondingBlocks is the delay between unstake and withdrawable
	// funds, protecting against long-range signer misbehavior.
	UnbondingBlocks uint64 = 14400 // ~1 day at 6s blocks

	// BaseFee is the minimum fee a transaction must offer.
	BaseFee uint64 = 1000
)

// Account is the state of one address.
type Account struct {
	// Balance is spendable native tokens (nano-PQ).
	Balance uint64
	// Nonce is the next valid transaction nonce for this account.
	Nonce uint64
	// Staked is locked stake (validator admission weight).
	Staked uint64
	// PendingUnbond is the amount awaiting the unbonding delay.
	PendingUnbond uint64
	// UnbondingAt is the height at which PendingUnbond becomes
	// spendable; 0 means no pending unstake.
	UnbondingAt uint64
	// PubKey is the registered PQ public key (nil until registered).
	PubKey []byte
	// SigScheme is the scheme of PubKey.
	SigScheme protocol.SignatureScheme
}

// Registered reports whether the account has an on-chain PQ key.
func (a *Account) Registered() bool { return len(a.PubKey) > 0 }

// State is the full world state: accounts plus chain metadata. Transitions
// are applied to a clone so failure never mutates the original.
type State struct {
	// Accounts maps address -> account.
	Accounts map[protocol.Address]*Account
	// Height is the last applied block height.
	Height uint64
	// LastBlockHash is the hash of the last applied block header.
	LastBlockHash protocol.Hash
}

// New returns an empty state at height 0.
func New() *State {
	return &State{Accounts: make(map[protocol.Address]*Account)}
}

// Errors returned by the state transition function. These are
// consensus-visible: nodes must reject the same transactions for the
// same reasons.
var (
	// ErrUnknownAccount is returned when a sender has no account.
	ErrUnknownAccount = errors.New("state: unknown account")
	// ErrInsufficientBalance covers spend + fee exceeding balance.
	ErrInsufficientBalance = errors.New("state: insufficient balance")
	// ErrInsufficientStake is returned for unstake above the staked amount.
	ErrInsufficientStake = errors.New("state: insufficient stake")
	// ErrInvalidNonce is returned for replayed or gapped nonces.
	ErrInvalidNonce = errors.New("state: invalid nonce")
	// ErrStakeTooLow is returned when staking below MinStake.
	ErrStakeTooLow = errors.New("state: stake below minimum")
	// ErrFeeTooLow is returned when fee < BaseFee.
	ErrFeeTooLow = errors.New("state: fee below base")
	// ErrZeroAmount is returned for zero-value transfers/unstakes.
	ErrZeroAmount = errors.New("state: zero amount")
	// ErrUnstakePending is returned when an unstake is already in flight.
	ErrUnstakePending = errors.New("state: unstake already pending")
	// ErrUnknownTxKind is returned for undefined transaction kinds.
	ErrUnknownTxKind = errors.New("state: unknown transaction kind")
	// ErrEmptyKey is returned for key registration with empty payload.
	ErrEmptyKey = errors.New("state: register key: empty payload")
)

// get returns the account for addr, creating a zero account if absent.
func (s *State) get(addr protocol.Address) *Account {
	a, ok := s.Accounts[addr]
	if !ok {
		a = &Account{}
		s.Accounts[addr] = a
	}
	return a
}

// Clone deep-copies the state. ApplyBlock/ApplyTransaction work on a
// clone and only publish it on success, giving atomic semantics.
func (s *State) Clone() *State {
	accounts := make(map[protocol.Address]*Account, len(s.Accounts))
	for addr, a := range s.Accounts {
		cp := *a
		cp.PubKey = append([]byte(nil), a.PubKey...)
		accounts[addr] = &cp
	}
	return &State{Accounts: accounts, Height: s.Height, LastBlockHash: s.LastBlockHash}
}

// ApplyTransaction applies one transaction to a cloned state and returns
// the clone. On error the receiver is unchanged. Signature verification
// is the caller's job (see VerifyTransaction); state enforces accounting.
func (s *State) ApplyTransaction(tx *protocol.Transaction) (*State, error) {
	next := s.Clone()
	if err := next.applyTx(tx); err != nil {
		return nil, err
	}
	return next, nil
}

// applyTx mutates the state per the transaction kind.
func (s *State) applyTx(tx *protocol.Transaction) error {
	if tx.Fee < BaseFee {
		return ErrFeeTooLow
	}
	from, ok := s.Accounts[tx.Sender]
	if !ok {
		return ErrUnknownAccount
	}
	if from.Nonce != tx.Nonce {
		return ErrInvalidNonce
	}
	if from.Balance < tx.Fee {
		return ErrInsufficientBalance
	}
	from.Balance -= tx.Fee
	from.Nonce++

	switch tx.Kind {
	case protocol.TxTransfer:
		return s.applyTransfer(from, tx)
	case protocol.TxStake:
		return s.applyStake(from, tx)
	case protocol.TxUnstake:
		return s.applyUnstake(from, tx)
	case protocol.TxRegisterKey:
		return s.applyRegisterKey(from, tx)
	default:
		return fmt.Errorf("%w: %d", ErrUnknownTxKind, tx.Kind)
	}
}

// applyTransfer moves amount from sender to recipient.
func (s *State) applyTransfer(from *Account, tx *protocol.Transaction) error {
	if tx.Amount == 0 {
		return ErrZeroAmount
	}
	if from.Balance < tx.Amount {
		return ErrInsufficientBalance
	}
	from.Balance -= tx.Amount
	to := s.get(tx.To)
	to.Balance += tx.Amount
	return nil
}

// applyStake locks amount as validator stake.
func (s *State) applyStake(from *Account, tx *protocol.Transaction) error {
	if tx.Amount < MinStake {
		return ErrStakeTooLow
	}
	if from.Balance < tx.Amount {
		return ErrInsufficientBalance
	}
	from.Balance -= tx.Amount
	from.Staked += tx.Amount
	return nil
}

// applyUnstake starts the unbonding delay for amount.
func (s *State) applyUnstake(from *Account, tx *protocol.Transaction) error {
	if tx.Amount == 0 {
		return ErrZeroAmount
	}
	if from.Staked < tx.Amount {
		return ErrInsufficientStake
	}
	if from.UnbondingAt != 0 {
		return ErrUnstakePending
	}
	from.Staked -= tx.Amount
	from.PendingUnbond = tx.Amount
	// Principal is credited at the unbonding height, not now: until then
	// it is neither staked nor spendable.
	from.UnbondingAt = s.Height + UnbondingBlocks + 1
	return nil
}

// applyRegisterKey binds or rotates the sender's public key (carried in
// Payload; SigScheme selects the algorithm). Rotation is the migration
// path if a scheme is ever broken.
func (s *State) applyRegisterKey(from *Account, tx *protocol.Transaction) error {
	if len(tx.Payload) == 0 {
		return ErrEmptyKey
	}
	from.PubKey = append(from.PubKey[:0], tx.Payload...)
	from.SigScheme = tx.SigScheme
	return nil
}

// SettleUnbondings credits balances for unstakes whose unbonding height
// has arrived. Called once per block after applying its transactions.
func (s *State) SettleUnbondings() {
	for _, a := range s.Accounts {
		if a.UnbondingAt != 0 && a.UnbondingAt <= s.Height {
			a.Balance += a.PendingUnbond
			a.PendingUnbond = 0
			a.UnbondingAt = 0
		}
	}
}

// TotalSupply sums all balances, stakes and pending unbonds. Used by
// tests and explorers to check the ledger is closed.
func (s *State) TotalSupply() uint64 {
	var total uint64
	for _, a := range s.Accounts {
		total += a.Balance + a.Staked + a.PendingUnbond
	}
	return total
}
