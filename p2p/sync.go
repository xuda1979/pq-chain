package p2p

import (
	"fmt"

	"github.com/xuda1979/pq-chain/protocol"
)

// Sync walks a peer's chain header-first: fetch headers, validate the
// linkage (each header's PrevHash matches the previous header hash, and
// heights are contiguous), then fetch the matching blocks. Blocks are
// returned through fn in ascending height order so the caller can append
// them to its store and apply them to consensus state.
//
// Header-first sync bounds the harm a malicious peer can do: headers are
// small, linkage is cheap to verify, and only a peer who supplies a
// linkage-valid header chain gets its blocks fetched. Signature
// verification of individual blocks remains the caller's responsibility
// (it needs the proposer keys, which live in consensus state).
func Sync(
	peer *Peer,
	localHeight uint64,
	step uint32,
	fn func(b *protocol.Block) error,
) (uint64, error) {
	start := localHeight + 1
	if peer.Height() < start {
		return localHeight, nil // nothing to do
	}
	if step == 0 || step > MaxHeadersPerResponse {
		step = MaxHeadersPerResponse
	}

	var lastHash protocol.Hash
	var haveLast bool
	for start <= peer.Height() {
		got, err := GetHeaders(peer, start, step)
		if err != nil {
			return 0, err
		}
		if len(got) == 0 {
			return 0, fmt.Errorf("p2p: peer %x returned no headers for %d", peer.id[:4], start)
		}
		want := start
		for _, h := range got {
			if h.Height != want {
				return 0, fmt.Errorf("p2p: header at %d, want %d (peer %x)", h.Height, want, peer.id[:4])
			}
			if haveLast && h.PrevHash != lastHash {
				return 0, fmt.Errorf("p2p: header %d breaks linkage (peer %x)", h.Height, peer.id[:4])
			}
			lastHash = h.Hash()
			haveLast = true
			want++
		}
		// Fetch blocks for this batch.
		for _, h := range got {
			b, err := GetBlock(peer, h.Height)
			if err != nil {
				return 0, err
			}
			// Caller-visible invariant: block hash must match its header.
			if b.Header.Hash() != h.Hash() {
				return 0, fmt.Errorf("p2p: block %d hash mismatch (peer %x)", h.Height, peer.id[:4])
			}
			if err := fn(b); err != nil {
				return 0, err
			}
		}
		start = want
	}
	return start - 1, nil
}
