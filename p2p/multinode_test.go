package p2p

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/xuda1979/pq-chain/protocol"
)

// TestMultiNodeSyncMesh simulates a small network of nodes on one
// machine: one authoritative seed node holds the full chain, several
// peers sync from it concurrently (as fresh nodes do on join), and one
// late joiner syncs from a peer that has already synced — covering both
// the seed path and the cascading-sync path a real network takes.
func TestMultiNodeSyncMesh(t *testing.T) {
	reg, newsuite := testRegistry(t)

	// Seed node with a 120-block chain.
	seedChain := newMemChain(120)
	seedID, err := NewIdentity(newsuite())
	if err != nil {
		t.Fatal(err)
	}
	seedCfg := Config{Version: ProtocolVersion, Registry: reg, NewSuite: newsuite, Chain: seedChain}
	seed, err := Listen(seedCfg, seedID, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go seed.Serve(ctx)

	// runNode boots a fresh node (empty chain), syncs from addr, and
	// returns the heights it received.
	runNode := func(name, addr string) ([]uint64, error) {
		chain := newMemChain(0)
		id, err := NewIdentity(newsuite())
		if err != nil {
			return nil, err
		}
		cfg := Config{Version: ProtocolVersion, Registry: reg, NewSuite: newsuite, Chain: chain}
		client := NewClient(cfg, id)
		peer, err := client.Dial(addr)
		if err != nil {
			return nil, fmt.Errorf("%s dial: %w", name, err)
		}
		defer peer.Close()
		var heights []uint64
		if _, err := Sync(peer, 0, 25, func(b *protocol.Block) error {
			heights = append(heights, b.Header.Height)
			chain.blocks = append(chain.blocks, b)
			chain.headers = append(chain.headers, b.Header)
			return nil
		}); err != nil {
			return nil, fmt.Errorf("%s sync: %w", name, err)
		}
		return heights, nil
	}

	// Three nodes join concurrently straight from the seed.
	const direct = 3
	results := make([][]uint64, direct)
	errs := make([]error, direct)
	var wg sync.WaitGroup
	for i := 0; i < direct; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = runNode(fmt.Sprintf("node-%d", i), seed.Addr().String())
		}(i)
	}
	wg.Wait()
	for i := 0; i < direct; i++ {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if len(results[i]) != 120 {
			t.Fatalf("node-%d got %d blocks, want 120", i, len(results[i]))
		}
		for j, h := range results[i] {
			if h != uint64(j+1) {
				t.Fatalf("node-%d height %d out of order at %d", i, h, j)
			}
		}
	}

	// A node that synced from the seed now serves a late joiner itself:
	// cascading sync, the topology a growing network actually forms.
	relayChain := newMemChain(120)
	relayChain.blocks = nil
	relayChain.headers = nil
	for _, h := range results[0] {
		b, err := seedChain.Block(h)
		if err != nil {
			t.Fatal(err)
		}
		relayChain.blocks = append(relayChain.blocks, b)
		relayChain.headers = append(relayChain.headers, b.Header)
	}
	relayID, err := NewIdentity(newsuite())
	if err != nil {
		t.Fatal(err)
	}
	relayCfg := Config{Version: ProtocolVersion, Registry: reg, NewSuite: newsuite, Chain: relayChain}
	relay, err := Listen(relayCfg, relayID, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	go relay.Serve(ctx)

	lateHeights, err := runNode("late-joiner", relay.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if len(lateHeights) != 120 {
		t.Fatalf("late joiner got %d blocks, want 120", len(lateHeights))
	}
}

// TestSyncRejectsBrokenLinkage proves the sync path refuses a header
// chain that does not link: a malicious peer serving fabricated headers
// cannot push blocks through Sync.
func TestSyncRejectsBrokenLinkage(t *testing.T) {
	reg, newsuite := testRegistry(t)

	// 10 honest blocks + a fabricated header 11 that links to nothing.
	honest := newMemChain(10)
	fake := protocol.BlockHeader{Version: 1, Height: 11, PrevHash: protocol.ZeroHash}
	honest.headers = append(honest.headers, fake)

	id, err := NewIdentity(newsuite())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Version: ProtocolVersion, Registry: reg, NewSuite: newsuite, Chain: honest}
	srv, err := Listen(cfg, id, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	clientID, err := NewIdentity(newsuite())
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(cfg, clientID)
	peer, err := client.Dial(srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	var accepted int
	_, err = Sync(peer, 0, 20, func(b *protocol.Block) error {
		accepted++
		return nil
	})
	if err == nil {
		t.Fatal("sync accepted a broken-linkage header chain")
	}
	if accepted > 10 {
		t.Fatalf("sync applied %d blocks despite linkage break", accepted)
	}
}

// TestHandshakeRejectsWrongChainID pins identity binding on the wire: a
// handshake signed for a DIFFERENT node address (impersonation attempt)
// must fail verification because BytesToSign covers the address.
func TestHandshakeRejectsImpersonation(t *testing.T) {
	reg, newsuite := testRegistry(t)
	honestID, err := NewIdentity(newsuite())
	if err != nil {
		t.Fatal(err)
	}
	attackerID, err := NewIdentity(newsuite())
	if err != nil {
		t.Fatal(err)
	}

	// Attacker signs a handshake claiming the honest node's address.
	addr, err := honestID.Address()
	if err != nil {
		t.Fatal(err)
	}
	h := &Handshake{Address: addr, Height: 1}
	copy(h.Nonce[:], randomNonce())
	// Sign with the ATTACKER's key: signHandshake stamps the attacker's
	// scheme and public key, so the derived-address check in Verify must
	// fail (attacker key does not derive to the claimed address).
	if err := attackerID.signHandshake(newsuite(), h); err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(reg); err == nil {
		t.Fatal("impersonated handshake verified")
	}
}
