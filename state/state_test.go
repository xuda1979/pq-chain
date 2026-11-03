package state

import (
	"bytes"
	"testing"

	"github.com/your-org/pq-chain-public/crypto"
	"github.com/your-org/pq-chain-public/protocol"
)

// newTestChain builds a genesis state with one funded account that has a
// registered ML-DSA-65 key, plus the signing/verification machinery.
func newTestChain(t *testing.T) (*State, *crypto.Registry, *crypto.MLDSASuite, crypto.PublicKey, crypto.PrivateKey) {
	t.Helper()
	suite := crypto.NewMLDSA65()
	reg := crypto.NewRegistry()
	if err := reg.Register(suite); err != nil {
		t.Fatal(err)
	}
	pk, sk, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := crypto.DeriveAddress(protocol.SchemeMLDSA65, pk)
	if err != nil {
		t.Fatal(err)
	}

	s := New()
	acc := &Account{Balance: 10_000 * MinStake, Nonce: 0}
	s.Accounts[addr] = acc
	// Register the key directly in genesis state for testing.
	if err := register(s, addr, pk); err != nil {
		t.Fatal(err)
	}
	s.Height = 1
	s.LastBlockHash = protocol.ZeroHash
	return s, reg, suite, pk, sk
}

// newStakedProposer registers a funded, staked proposer account and
// returns its address and signing key.
func newStakedProposer(t *testing.T, s *State, suite *crypto.MLDSASuite) (protocol.Address, crypto.PrivateKey) {
	t.Helper()
	pk, sk, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := crypto.DeriveAddress(protocol.SchemeMLDSA65, pk)
	if err != nil {
		t.Fatal(err)
	}
	s.Accounts[addr] = &Account{Balance: 100 * MinStake, Staked: MinStake}
	if err := register(s, addr, pk); err != nil {
		t.Fatal(err)
	}
	return addr, sk
}

func register(s *State, addr protocol.Address, pk crypto.PublicKey) error {
	a, ok := s.Accounts[addr]
	if !ok {
		a = &Account{}
		s.Accounts[addr] = a
	}
	a.PubKey = append([]byte(nil), pk...)
	a.SigScheme = protocol.SchemeMLDSA65
	return nil
}

// signedTx builds a signed transaction for the test account.
func signedTx(t *testing.T, suite *crypto.MLDSASuite, sk crypto.PrivateKey, sender protocol.Address, nonce uint64, kind uint8, to protocol.Address, amount, fee uint64) *protocol.Transaction {
	t.Helper()
	tx := &protocol.Transaction{
		Sender:    sender,
		Nonce:     nonce,
		Kind:      kind,
		To:        to,
		Amount:    amount,
		Fee:       fee,
		SigScheme: protocol.SchemeMLDSA65,
	}
	sig, err := suite.Sign(sk, tx.SignBytes())
	if err != nil {
		t.Fatal(err)
	}
	tx.Signature = sig
	return tx
}

func TestTransferLifecycle(t *testing.T) {
	s, reg, suite, pk, sk := newTestChain(t)
	_ = pk
	sender := senderAddr(t, s)
	recipient := protocol.Address{9}

	// fund recipient with an account so transfers to it work
	s.Accounts[recipient] = &Account{Balance: 0}

	tx := signedTx(t, suite, sk, sender, 0, protocol.TxTransfer, recipient, 5*MinStake, 2*BaseFee)
	if err := VerifyTransaction(s, reg, tx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	next, err := s.ApplyTransaction(tx)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := next.Accounts[sender].Balance; got != 10_000*MinStake-5*MinStake-2*BaseFee {
		t.Fatalf("sender balance = %d", got)
	}
	if got := next.Accounts[recipient].Balance; got != 5*MinStake {
		t.Fatalf("recipient balance = %d", got)
	}
	// Original state must be untouched (atomicity).
	if got := s.Accounts[sender].Balance; got != 10_000*MinStake {
		t.Fatalf("parent state mutated: %d", got)
	}
	if got := s.Accounts[sender].Nonce; got != 0 {
		t.Fatalf("parent nonce mutated: %d", got)
	}
}

func TestNonceReplayProtection(t *testing.T) {
	s, _, suite, _, sk := newTestChain(t)
	sender := senderAddr(t, s)
	recipient := protocol.Address{9}
	s.Accounts[recipient] = &Account{}

	tx := signedTx(t, suite, sk, sender, 0, protocol.TxTransfer, recipient, MinStake, BaseFee)
	s, err := s.ApplyTransaction(tx)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// Same nonce again must fail even though balance is ample.
	if _, err := s.ApplyTransaction(tx); err == nil {
		t.Fatal("replayed transaction accepted")
	}
	// Skipping a nonce must fail too.
	tx2 := signedTx(t, suite, sk, sender, 2, protocol.TxTransfer, recipient, MinStake, BaseFee)
	if _, err := s.ApplyTransaction(tx2); err == nil {
		t.Fatal("gapped nonce accepted")
	}
}

func TestStakeUnstakeUnbonding(t *testing.T) {
	s, _, suite, _, sk := newTestChain(t)
	sender := senderAddr(t, s)

	stake := signedTx(t, suite, sk, sender, 0, protocol.TxStake, protocol.Address{}, 100*MinStake, BaseFee)
	s, err := s.ApplyTransaction(stake)
	if err != nil {
		t.Fatalf("stake: %v", err)
	}
	if got := s.Accounts[sender].Staked; got != 100*MinStake {
		t.Fatalf("staked = %d", got)
	}

	unstake := signedTx(t, suite, sk, sender, 1, protocol.TxUnstake, protocol.Address{}, 40*MinStake, BaseFee)
	s, err = s.ApplyTransaction(unstake)
	if err != nil {
		t.Fatalf("unstake: %v", err)
	}
	acc := s.Accounts[sender]
	if acc.Staked != 60*MinStake || acc.PendingUnbond != 40*MinStake {
		t.Fatalf("staked=%d pending=%d", acc.Staked, acc.PendingUnbond)
	}

	// Funds are locked until the unbonding height passes.
	balanceBefore := acc.Balance
	s.SettleUnbondings()
	if s.Accounts[sender].Balance != balanceBefore {
		t.Fatal("unbond released early")
	}

	// Advance past the unbonding height and settle.
	s.Height += UnbondingBlocks + 1
	s.SettleUnbondings()
	if got := s.Accounts[sender].Balance; got != balanceBefore+40*MinStake {
		t.Fatalf("unbond not settled: %d", got)
	}
	if s.Accounts[sender].PendingUnbond != 0 || s.Accounts[sender].UnbondingAt != 0 {
		t.Fatal("unbond state not cleared")
	}
}

func TestKeyRotation(t *testing.T) {
	s, _, suite, pk, sk := newTestChain(t)
	sender := senderAddr(t, s)
	if !s.Accounts[sender].Registered() {
		t.Fatal("test account should start registered")
	}
	if !bytes.Equal(s.Accounts[sender].PubKey, pk) {
		t.Fatal("registered key mismatch")
	}

	// Rotate to a fresh ML-DSA-65 key.
	newSuite := crypto.NewMLDSA65()
	newPK, newSK, err := newSuite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	tx := &protocol.Transaction{
		Sender:    sender,
		Nonce:     0,
		Kind:      protocol.TxRegisterKey,
		Amount:    0,
		Fee:       BaseFee,
		Payload:   newPK,
		SigScheme: protocol.SchemeMLDSA65,
	}
	sig, err := suite.Sign(sk, tx.SignBytes())
	if err != nil {
		t.Fatal(err)
	}
	tx.Signature = sig

	next, err := s.ApplyTransaction(tx)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !bytes.Equal(next.Accounts[sender].PubKey, newPK) {
		t.Fatal("rotation did not update key")
	}
	_ = newSK
}

func TestFeeFloorAndUnknownKind(t *testing.T) {
	s, _, suite, _, sk := newTestChain(t)
	sender := senderAddr(t, s)
	tx := signedTx(t, suite, sk, sender, 0, protocol.TxTransfer, protocol.Address{9}, MinStake, BaseFee-1)
	if _, err := s.ApplyTransaction(tx); err == nil {
		t.Fatal("below-base fee accepted")
	}
	bad := signedTx(t, suite, sk, sender, 0, 99, protocol.Address{9}, MinStake, BaseFee)
	if _, err := s.ApplyTransaction(bad); err == nil {
		t.Fatal("unknown kind accepted")
	}
}

func TestApplyBlockValidatesAndRoutesFees(t *testing.T) {
	s, reg, suite, pk, sk := newTestChain(t)
	sender := senderAddr(t, s)
	proposer, proposerSK := newStakedProposer(t, s, suite)

	// Set up parent block linkage.
	parentHeader := &protocol.BlockHeader{Version: 1, Height: 1, Proposer: proposer}
	s.LastBlockHash = parentHeader.Hash()
	s.Height = 1

	recipient := protocol.Address{9}
	s.Accounts[recipient] = &Account{}

	tx1 := signedTx(t, suite, sk, sender, 0, protocol.TxTransfer, recipient, 3*MinStake, 5*BaseFee)
	tx2 := signedTx(t, suite, sk, sender, 1, protocol.TxStake, protocol.Address{}, 2*MinStake, 7*BaseFee)

	block := &protocol.Block{
		Header: protocol.BlockHeader{
			Version:   1,
			Height:    2,
			Timestamp: 1730000000000,
			PrevHash:  parentHeader.Hash(),
			Proposer:  proposer,
		},
		Transactions: []*protocol.Transaction{tx1, tx2},
	}
	block.Header.TxRoot = block.ComputeTxRoot()
	signBlock(t, suite, proposerSK, &block.Header)

	// Tamper the root: must be rejected.
	tampered := *block
	tampered.Header = block.Header
	tampered.Header.TxRoot = protocol.ZeroHash
	if _, err := ApplyBlock(s, reg, &tampered); err == nil {
		t.Fatal("tampered tx root accepted")
	}

	// Unsigned header: must be rejected (anyone could else claim fees).
	unsigned := *block
	unsigned.Header = block.Header
	unsigned.Header.ProposerSig = nil
	if _, err := ApplyBlock(s, reg, &unsigned); err == nil {
		t.Fatal("unsigned header accepted")
	}

	// Unstaked proposer: must be rejected.
	unstaked := s.Clone()
	unstaked.Accounts[proposer].Staked = 0
	if _, err := ApplyBlock(unstaked, reg, block); err == nil {
		t.Fatal("unstaked proposer accepted")
	}

	// Wrong block version: must be rejected.
	badVer := *block
	badVer.Header = block.Header
	badVer.Header.Version = 99
	if _, err := ApplyBlock(s, reg, &badVer); err == nil {
		t.Fatal("bad version accepted")
	}

	next, err := ApplyBlock(s, reg, block)
	if err != nil {
		t.Fatalf("apply block: %v", err)
	}
	if next.Height != 2 {
		t.Fatalf("height = %d", next.Height)
	}
	if !next.LastBlockHash.Equal(block.Header.Hash()) {
		t.Fatal("last block hash not updated")
	}
	if got := next.Accounts[proposer].Balance; got != 100*MinStake+12*BaseFee {
		t.Fatalf("proposer fees = %d, want %d", got, 100*MinStake+12*BaseFee)
	}
	if got := next.Accounts[recipient].Balance; got != 3*MinStake {
		t.Fatalf("recipient = %d", got)
	}
	if got := next.Accounts[sender].Staked; got != 2*MinStake {
		t.Fatalf("staked = %d", got)
	}
	_ = pk
}

// signBlock signs a block header in place with the proposer's key.
func signBlock(t *testing.T, suite *crypto.MLDSASuite, sk crypto.PrivateKey, h *protocol.BlockHeader) {
	t.Helper()
	sig, err := suite.Sign(sk, h.SignBytes())
	if err != nil {
		t.Fatal(err)
	}
	h.ProposerSig = sig
}

func TestTotalSupplyConservation(t *testing.T) {
	s, _, suite, _, sk := newTestChain(t)
	sender := senderAddr(t, s)
	recipient := protocol.Address{9}
	s.Accounts[recipient] = &Account{}

	before := s.TotalSupply()
	for i := 0; i < 5; i++ {
		tx := signedTx(t, suite, sk, sender, uint64(i), protocol.TxTransfer, recipient, MinStake, BaseFee)
		next, err := s.ApplyTransaction(tx)
		if err != nil {
			t.Fatalf("tx %d: %v", i, err)
		}
		s = next
	}
	// Standalone transaction fees are burned until a proposer collects
	// them in a block, so supply drops by exactly the burned fees.
	burned := 5 * BaseFee
	if after := s.TotalSupply(); after != before-burned {
		t.Fatalf("supply: before=%d after=%d want=%d", before, after, before-burned)
	}
}

// senderAddr finds the single funded account address in the test state.
func senderAddr(t *testing.T, s *State) protocol.Address {
	t.Helper()
	if len(s.Accounts) != 1 {
		t.Fatalf("expected 1 genesis account, got %d", len(s.Accounts))
	}
	for addr := range s.Accounts {
		return addr
	}
	return protocol.Address{}
}
