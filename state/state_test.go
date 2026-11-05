package state

import (
	"bytes"
	"strings"
	"testing"
	"time"

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

// TestEnrollmentSelfCertifying covers the first-registration path: an
// unregistered account may ONLY send TxRegisterKey, the payload key must
// derive to the sender address, and once registered the account can send
// ordinary transactions.
func TestEnrollmentSelfCertifying(t *testing.T) {
	s, reg, _, _, _ := newTestChain(t)
	fresh := crypto.NewMLDSA65()
	freshPK, freshSK, err := fresh.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := crypto.DeriveAddress(protocol.SchemeMLDSA65, freshPK)
	if err != nil {
		t.Fatal(err)
	}
	// Fund but do not register.
	s.Accounts[addr] = &Account{Balance: 100 * MinStake}

	// Non-register tx from an unregistered account: rejected.
	bad := &protocol.Transaction{
		Sender: addr, Nonce: 0, Kind: protocol.TxTransfer,
		To: protocol.Address{9}, Amount: MinStake, Fee: BaseFee,
		SigScheme: protocol.SchemeMLDSA65,
	}
	if sig, err := fresh.Sign(freshSK, bad.SignBytes()); err != nil {
		t.Fatal(err)
	} else {
		bad.Signature = sig
	}
	if err := VerifyTransaction(s, reg, bad); err == nil {
		t.Fatal("transfer from unregistered account accepted")
	}

	// Enrollment whose payload key does NOT derive to the sender: rejected.
	otherPK, _, err := fresh.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrong := &protocol.Transaction{
		Sender: addr, Nonce: 0, Kind: protocol.TxRegisterKey,
		Fee: BaseFee, Payload: otherPK, SigScheme: protocol.SchemeMLDSA65,
	}
	if sig, err := fresh.Sign(freshSK, wrong.SignBytes()); err != nil {
		t.Fatal(err)
	} else {
		wrong.Signature = sig
	}
	if err := VerifyTransaction(s, reg, wrong); err == nil {
		t.Fatal("enrollment with mismatched key accepted")
	}

	// Malformed payload (wrong size for the scheme): rejected.
	garbage := &protocol.Transaction{
		Sender: addr, Nonce: 0, Kind: protocol.TxRegisterKey,
		Fee: BaseFee, Payload: []byte{1, 2, 3}, SigScheme: protocol.SchemeMLDSA65,
	}
	if sig, err := fresh.Sign(freshSK, garbage.SignBytes()); err != nil {
		t.Fatal(err)
	} else {
		garbage.Signature = sig
	}
	if _, err := s.ApplyTransaction(garbage); err == nil {
		t.Fatal("malformed enrollment payload accepted")
	}

	// Correct enrollment: accepted, account becomes registered.
	enroll := &protocol.Transaction{
		Sender: addr, Nonce: 0, Kind: protocol.TxRegisterKey,
		Fee: BaseFee, Payload: freshPK, SigScheme: protocol.SchemeMLDSA65,
	}
	sig, err := fresh.Sign(freshSK, enroll.SignBytes())
	if err != nil {
		t.Fatal(err)
	}
	enroll.Signature = sig
	next, err := s.ApplyTransaction(enroll)
	if err != nil {
		t.Fatalf("enrollment: %v", err)
	}
	if !next.Accounts[addr].Registered() {
		t.Fatal("account not registered after enrollment")
	}

	// Now ordinary transactions work.
	tx := &protocol.Transaction{
		Sender: addr, Nonce: 1, Kind: protocol.TxTransfer,
		To: protocol.Address{9}, Amount: MinStake, Fee: BaseFee,
		SigScheme: protocol.SchemeMLDSA65,
	}
	if sig, err := fresh.Sign(freshSK, tx.SignBytes()); err != nil {
		t.Fatal(err)
	} else {
		tx.Signature = sig
	}
	if err := VerifyTransaction(next, reg, tx); err != nil {
		t.Fatalf("post-enrollment transfer: %v", err)
	}
}

// TestCrossSchemeRotation rotates a registered ML-DSA-65 account to an
// ML-DSA-44 key: the rotation signature is made with the OLD key (which
// authorizes it), the new scheme rides in Payload/SigScheme, and after
// rotation the account signs with the new scheme.
func TestCrossSchemeRotation(t *testing.T) {
	s, reg, _, _, sk := newTestChain(t)
	sender := senderAddr(t, s)

	newSuite := crypto.NewMLDSA44()
	newPK, newSK, err := newSuite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(newSuite); err != nil {
		t.Fatal(err)
	}

	rotate := &protocol.Transaction{
		Sender: sender, Nonce: 0, Kind: protocol.TxRegisterKey,
		Fee: BaseFee, Payload: newPK, SigScheme: protocol.SchemeMLDSA44,
	}
	// Signed with the OLD (registered) key — that is the authorization.
	oldSuite := crypto.NewMLDSA65()
	sig, err := oldSuite.Sign(sk, rotate.SignBytes())
	if err != nil {
		t.Fatal(err)
	}
	rotate.Signature = sig

	next, err := s.ApplyTransaction(rotate)
	if err != nil {
		t.Fatalf("cross-scheme rotation: %v", err)
	}
	acc := next.Accounts[sender]
	if acc.SigScheme != protocol.SchemeMLDSA44 {
		t.Fatalf("scheme = %s, want ML-DSA-44", acc.SigScheme)
	}
	if !bytes.Equal(acc.PubKey, newPK) {
		t.Fatal("rotated key not installed")
	}

	// After rotation the account signs with the NEW scheme.
	tx := &protocol.Transaction{
		Sender: sender, Nonce: 1, Kind: protocol.TxTransfer,
		To: protocol.Address{9}, Amount: MinStake, Fee: BaseFee,
		SigScheme: protocol.SchemeMLDSA44,
	}
	sig2, err := newSuite.Sign(newSK, tx.SignBytes())
	if err != nil {
		t.Fatal(err)
	}
	tx.Signature = sig2
	if err := VerifyTransaction(next, reg, tx); err != nil {
		t.Fatalf("post-rotation tx under new scheme: %v", err)
	}

	// A signature under the OLD key no longer authorizes anything.
	stale := &protocol.Transaction{
		Sender: sender, Nonce: 2, Kind: protocol.TxTransfer,
		To: protocol.Address{9}, Amount: MinStake, Fee: BaseFee,
		SigScheme: protocol.SchemeMLDSA65,
	}
	sig3, err := oldSuite.Sign(sk, stale.SignBytes())
	if err != nil {
		t.Fatal(err)
	}
	stale.Signature = sig3
	if err := VerifyTransaction(next, reg, stale); err == nil {
		t.Fatal("old-scheme tx accepted after rotation")
	}
}

// TestBlockTimestampValidation exercises the chain clock: timestamps must
// be strictly increasing and must not drift too far into the future.
func TestBlockTimestampValidation(t *testing.T) {
	s, reg, suite, _, _ := newTestChain(t)
	proposer, proposerSK := newStakedProposer(t, s, suite)
	parent := &protocol.BlockHeader{Version: 1, Height: 1, Proposer: proposer}
	s.LastBlockHash = parent.Hash()
	s.Height = 1
	_ = reg

	now := uint64(time.Now().UnixMilli())
	makeBlock := func(ts uint64, prevTime uint64) *protocol.Block {
		child := s.Clone()
		child.LastBlockTime = prevTime
		b := &protocol.Block{Header: protocol.BlockHeader{
			Version: 1, Height: 2, Timestamp: ts,
			PrevHash: parent.Hash(), Proposer: proposer,
		}}
		b.Header.TxRoot = b.ComputeTxRoot()
		signBlock(t, suite, proposerSK, &b.Header)
		return b
	}

	// Non-monotonic timestamp: rejected.
	if _, err := ApplyBlock(mkState(s, 1000), reg, makeBlock(999, 1000)); err == nil {
		t.Fatal("non-monotonic timestamp accepted")
	}
	// Equal timestamp: rejected.
	if _, err := ApplyBlock(mkState(s, 1000), reg, makeBlock(1000, 1000)); err == nil {
		t.Fatal("equal timestamp accepted")
	}
	// Far-future timestamp: rejected.
	far := now + uint64(MaxFutureBlockTime/time.Millisecond) + 60_000
	if _, err := ApplyBlock(mkState(s, 1000), reg, makeBlock(far, 1000)); err == nil {
		t.Fatal("far-future timestamp accepted")
	}
	// Valid timestamp: accepted, and LastBlockTime advances.
	valid := now - 1000
	next, err := ApplyBlock(mkState(s, 1000), reg, makeBlock(valid, 1000))
	if err != nil {
		t.Fatalf("valid timestamp rejected: %v", err)
	}
	if next.LastBlockTime != valid {
		t.Fatalf("LastBlockTime = %d, want %d", next.LastBlockTime, valid)
	}
}

// mkState returns s with LastBlockTime overridden, for timestamp tests.
func mkState(s *State, lastTime uint64) *State {
	c := s.Clone()
	c.LastBlockTime = lastTime
	return c
}

// TestClockSkewDivergence pins the documented deployment constraint: two
// honest validators whose clocks differ by more than MaxFutureBlockTime
// DISAGREE about a block near the future boundary — this is the fork risk
// that makes NTP mandatory on validator hosts. Nodes within the skew
// window must agree on the same chain.
func TestClockSkewDivergence(t *testing.T) {
	s, reg, suite, _, _ := newTestChain(t)
	proposer, proposerSK := newStakedProposer(t, s, suite)
	parent := &protocol.BlockHeader{Version: 1, Height: 1, Proposer: proposer}
	s.LastBlockHash = parent.Hash()
	s.Height = 1

	base := time.Now()
	// One proposer clock, two verifying nodes with 3 minutes of skew
	// between them (beyond the 2-minute future window).
	nodeAClock := base
	nodeBClock := base.Add(3 * time.Minute)

	makeBlock := func(ts uint64) *protocol.Block {
		b := &protocol.Block{Header: protocol.BlockHeader{
			Version: 1, Height: 2, Timestamp: ts,
			PrevHash: parent.Hash(), Proposer: proposer,
		}}
		b.Header.TxRoot = b.ComputeTxRoot()
		signBlock(t, suite, proposerSK, &b.Header)
		return b
	}

	verifyAs := func(nodeClock time.Time, b *protocol.Block) error {
		old := nowFunc
		nowFunc = func() time.Time { return nodeClock }
		defer func() { nowFunc = old }()
		_, err := ApplyBlock(mkState(s, 1000), reg, b)
		return err
	}

	// A timestamp comfortably in both nodes' accepted windows: both
	// accept — consensus holds for ordinary blocks.
	safe := uint64(base.Add(-time.Minute).UnixMilli())
	b := makeBlock(safe)
	if err := verifyAs(nodeAClock, b); err != nil {
		t.Fatalf("node A rejected safe block: %v", err)
	}
	if err := verifyAs(nodeBClock, b); err != nil {
		t.Fatalf("node B rejected safe block: %v", err)
	}

	// A timestamp 150s ahead of node A (past its 120s window) but well
	// within node B's window (B's clock is 3min ahead): the nodes
	// disagree — the fork this test exists to document. Production
	// mitigation is NTP on every validator (see MaxFutureBlockTime docs).
	edge := uint64(base.Add(150 * time.Second).UnixMilli())
	bEdge := makeBlock(edge)
	errA := verifyAs(nodeAClock, bEdge)
	errB := verifyAs(nodeBClock, bEdge)
	if errA == nil {
		t.Fatal("node A accepted a block past its future window (want rejection)")
	}
	if errB != nil {
		t.Fatalf("node B rejected the same block its peer accepted: consensus fork: %v", errB)
	}
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

// TestApplyBlockManySenders builds a mainnet-scale block: hundreds of
// transactions from hundreds of distinct senders, all applied in one
// block. Every sender's nonce, balance, and fee routing must come out
// exactly right — a single crossed or dropped update is a consensus
// bug. Also guards the memory profile: one clone carries the block.
func TestApplyBlockManySenders(t *testing.T) {
	if testing.Short() {
		t.Skip("many-sender block in short mode")
	}
	s, reg, suite, _, _ := newTestChain(t)
	proposer, proposerSK := newStakedProposer(t, s, suite)
	parent := &protocol.BlockHeader{Version: 1, Height: 1, Proposer: proposer}
	s.LastBlockHash = parent.Hash()
	s.Height = 1

	const senders = 200
	const perSender = 3
	const amount = 5
	const fee = 2 * BaseFee

	type funded struct {
		addr protocol.Address
		sk   crypto.PrivateKey
	}
	accounts := make([]funded, senders)
	for i := range accounts {
		pk, sk, err := suite.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		addr, err := crypto.DeriveAddress(protocol.SchemeMLDSA65, pk)
		if err != nil {
			t.Fatal(err)
		}
		s.Accounts[addr] = &Account{Balance: 10_000 * MinStake}
		if err := register(s, addr, pk); err != nil {
			t.Fatal(err)
		}
		accounts[i] = funded{addr: addr, sk: sk}
	}

	txs := make([]*protocol.Transaction, 0, senders*perSender)
	var wantFees uint64
	for i, a := range accounts {
		for j := 0; j < perSender; j++ {
			tx := signedTx(t, suite, a.sk, a.addr, uint64(j), protocol.TxTransfer, protocol.Address{byte(i % 250), byte(j)}, amount, fee)
			txs = append(txs, tx)
			wantFees += fee
		}
	}

	block := &protocol.Block{
		Header: protocol.BlockHeader{
			Version:   1,
			Height:    2,
			Timestamp: uint64(time.Now().Add(-time.Minute).UnixMilli()),
			PrevHash:  parent.Hash(),
			Proposer:  proposer,
		},
		Transactions: txs,
	}
	block.Header.TxRoot = block.ComputeTxRoot()
	signBlock(t, suite, proposerSK, &block.Header)

	next, err := ApplyBlock(s, reg, block)
	if err != nil {
		t.Fatalf("apply %d-tx block: %v", len(txs), err)
	}

	// Every sender: nonce advanced, balance debited exactly amount+fee
	// per transaction.
	for _, a := range accounts {
		acc, ok := next.Accounts[a.addr]
		if !ok {
			t.Fatalf("sender account vanished")
		}
		if acc.Nonce != perSender {
			t.Fatalf("sender nonce = %d, want %d", acc.Nonce, perSender)
		}
		want := 10_000*MinStake - uint64(perSender)*(amount+fee)
		if acc.Balance != want {
			t.Fatalf("sender balance = %d, want %d", acc.Balance, want)
		}
	}
	// Proposer: original balance plus every fee.
	if got := next.Accounts[proposer].Balance; got != 100*MinStake+wantFees {
		t.Fatalf("proposer balance = %d, want %d", got, 100*MinStake+wantFees)
	}
	if next.Height != 2 {
		t.Fatalf("height = %d", next.Height)
	}
}

// TestApplyBlockRejectsOversizedBlock pins the consensus block-size limit:
// a block beyond MaxBlockTransactions must be rejected BEFORE any
// per-transaction work (hashing, signature verification) runs. This is
// the resource-exhaustion guard: verification cost per block must be
// bounded and known on every node.
func TestApplyBlockRejectsOversizedBlock(t *testing.T) {
	s, reg, suite, _, _ := newTestChain(t)
	proposer, proposerSK := newStakedProposer(t, s, suite)
	parent := &protocol.BlockHeader{Version: 1, Height: 1, Proposer: proposer}
	s.LastBlockHash = parent.Hash()
	s.Height = 1

	// One over the limit. Building MaxBlockTransactions+1 tiny
	// transactions is cheap; they never get verified because the limit
	// check runs first.
	txs := make([]*protocol.Transaction, protocol.MaxBlockTransactions+1)
	for i := range txs {
		txs[i] = &protocol.Transaction{Sender: protocol.Address{byte(i)}, Fee: 1}
	}
	block := &protocol.Block{
		Header: protocol.BlockHeader{
			Version: 1, Height: 2,
			Timestamp: uint64(time.Now().Add(-time.Minute).UnixMilli()),
			PrevHash:  parent.Hash(), Proposer: proposer,
		},
		Transactions: txs,
	}
	block.Header.TxRoot = block.ComputeTxRoot()
	signBlock(t, suite, proposerSK, &block.Header)

	if _, err := ApplyBlock(s, reg, block); err == nil {
		t.Fatal("block exceeding MaxBlockTransactions accepted")
	}

	// And exactly at the limit must NOT be rejected on the count (it will
	// fail later on signature checks, which is the correct reason).
	atLimit := make([]*protocol.Transaction, protocol.MaxBlockTransactions)
	for i := range atLimit {
		atLimit[i] = &protocol.Transaction{Sender: protocol.Address{byte(i)}, Fee: 1}
	}
	block.Transactions = atLimit
	block.Header.TxRoot = block.ComputeTxRoot()
	signBlock(t, suite, proposerSK, &block.Header)
	_, err := ApplyBlock(s, reg, block)
	if err == nil {
		t.Fatal("unsigned txs accepted")
	}
	if strings.Contains(err.Error(), "transactions, limit") {
		t.Fatalf("at-limit block rejected on the count check: %v", err)
	}
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
