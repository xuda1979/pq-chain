package p2p

import (
	"context"
	"fmt"
	"testing"

	"github.com/xuda1979/pq-chain/crypto"
	"github.com/xuda1979/pq-chain/protocol"
)

// memChain is an in-memory chain backend for tests.
type memChain struct {
	blocks  []*protocol.Block
	headers []protocol.BlockHeader
}

func newMemChain(n int) *memChain {
	m := &memChain{}
	for i := 1; i <= n; i++ {
		h := protocol.BlockHeader{Version: 1, Height: uint64(i), Timestamp: 1730000000000 + uint64(i*1000)}
		if i > 1 {
			h.PrevHash = m.blocks[i-2].Header.Hash()
		} else {
			h.PrevHash = protocol.ZeroHash
		}
		b := &protocol.Block{Header: h}
		b.Transactions = []*protocol.Transaction{
			{Nonce: uint64(i), Kind: protocol.TxTransfer, Amount: uint64(i), Fee: 5, SigScheme: protocol.SchemeMLDSA65},
		}
		h.TxRoot = b.ComputeTxRoot()
		h.ProposerSig = []byte{0x11, 0x22}
		b.Header = h
		m.blocks = append(m.blocks, b)
		m.headers = append(m.headers, h)
	}
	return m
}

// Height implements Chain.
func (m *memChain) Height() uint64 { return uint64(len(m.blocks)) }

// Headers implements Chain.
func (m *memChain) Headers(start uint64, count uint32) ([]protocol.BlockHeader, error) {
	if start < 1 || start > uint64(len(m.headers)) {
		return nil, fmt.Errorf("start %d out of range", start)
	}
	end := start + uint64(count)
	if end > uint64(len(m.headers)) {
		end = uint64(len(m.headers))
	}
	return m.headers[start-1 : end], nil
}

// Block implements Chain.
func (m *memChain) Block(height uint64) (*protocol.Block, error) {
	if height < 1 || height > uint64(len(m.blocks)) {
		return nil, fmt.Errorf("block %d out of range", height)
	}
	return m.blocks[height-1], nil
}

func testRegistry(t *testing.T) (*crypto.Registry, func() crypto.Signer) {
	t.Helper()
	suite := crypto.NewMLDSA65()
	reg := crypto.NewRegistry()
	if err := reg.Register(suite); err != nil {
		t.Fatal(err)
	}
	return reg, func() crypto.Signer { return crypto.NewMLDSA65() }
}

func TestHandshakeVerify(t *testing.T) {
	reg, newsuite := testRegistry(t)
	id, err := NewIdentity(newsuite())
	if err != nil {
		t.Fatal(err)
	}
	addr, err := id.Address()
	if err != nil {
		t.Fatal(err)
	}
	h := &Handshake{Address: addr, Height: 9}
	copy(h.Nonce[:], randomNonce())
	if err := id.signHandshake(newsuite(), h); err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(reg); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Corrupt the signature, must fail.
	h.Signature[0] ^= 0xFF
	if err := h.Verify(reg); err == nil {
		t.Fatal("corrupt signature must not verify")
	}
}

func TestMsgRoundTrip(t *testing.T) {
	msgs := []*Message{
		{Type: MsgHello, Version: ProtocolVersion, Height: 7},
		{Type: MsgGetHeaders, Start: 3, Count: 100},
		{Type: MsgGetBlock, BlockHeight: 5},
	}
	for _, m0 := range msgs {
		var m1 Message
		if err := m1.Unmarshal(m0.Marshal()); err != nil {
			t.Fatalf("roundtrip %d: %v", m0.Type, err)
		}
	}

	// Headers message.
	var hs []protocol.BlockHeader
	for i := uint64(1); i <= 3; i++ {
		h := protocol.BlockHeader{Version: 1, Height: i}
		hs = append(hs, h)
	}
	hm := &Message{Type: MsgHeaders, Headers: hs}
	var hm2 Message
	if err := hm2.Unmarshal(hm.Marshal()); err != nil {
		t.Fatal(err)
	}
	if len(hm2.Headers) != 3 || hm2.Headers[1].Height != 2 {
		t.Fatal("headers roundtrip mismatch")
	}

	// Block message.
	b := &protocol.Block{
		Header:       protocol.BlockHeader{Version: 1, Height: 4},
		Transactions: []*protocol.Transaction{{Nonce: 1, Kind: protocol.TxTransfer, SigScheme: protocol.SchemeMLDSA65}},
	}
	bm := &Message{Type: MsgBlock, Block: *b}
	var bm2 Message
	if err := bm2.Unmarshal(bm.Marshal()); err != nil {
		t.Fatal(err)
	}
	if bm2.Block.Header.Hash() != b.Header.Hash() {
		t.Fatal("block roundtrip mismatch")
	}
}

func TestSyncOverLoopback(t *testing.T) {
	reg, newsuite := testRegistry(t)

	serverChain := newMemChain(50)
	serverID, err := NewIdentity(newsuite())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Version: ProtocolVersion, Registry: reg, NewSuite: newsuite, Chain: serverChain}
	srv, err := Listen(cfg, serverID, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	// Second node with an empty chain syncs the whole 50 from the server.
	clientChain := newMemChain(0)
	clientID, err := NewIdentity(newsuite())
	if err != nil {
		t.Fatal(err)
	}
	ccfg := Config{Version: ProtocolVersion, Registry: reg, NewSuite: newsuite, Chain: clientChain}
	client := NewClient(ccfg, clientID)

	peer, err := client.Dial(srv.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer peer.Close()

	var got []uint64
	last, err := Sync(peer, 0, 10, func(b *protocol.Block) error {
		got = append(got, b.Header.Height)
		return nil
	})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if last != 50 {
		t.Fatalf("synced to %d, want 50", last)
	}
	if len(got) != 50 {
		t.Fatalf("got %d blocks, want 50", len(got))
	}
	for i, h := range got {
		if h != uint64(i+1) {
			t.Fatalf("height %d out of order at %d", h, i)
		}
	}

	// Idle sync (local already at head) is a no-op.
	localChain := serverChain
	if err := serverChain.reappend(0); err != nil {
		t.Fatal(err)
	}
	peer2, err := client.Dial(srv.Addr().String())
	if err != nil {
		t.Fatalf("dial2: %v", err)
	}
	defer peer2.Close()
	last2, err := Sync(peer2, 50, 10, func(b *protocol.Block) error { return nil })
	if err != nil {
		t.Fatalf("idle sync: %v", err)
	}
	if last2 != 50 {
		t.Fatalf("idle sync last=%d, want 50", last2)
	}
	_ = localChain
}

// reappend is a no-op stub the test uses to keep memChain valid.
func (m *memChain) reappend(n int) error { return nil }
