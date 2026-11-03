package protocol

// BlockHeader carries the consensus-critical fields of a block.
type BlockHeader struct {
	// Version is the block format version (currently 1).
	Version uint32
	// Height is the 1-based block number (genesis is height 1).
	Height uint64
	// Timestamp is the proposer's unix time in milliseconds.
	Timestamp uint64
	// PrevHash is the hash of the parent block header.
	PrevHash Hash
	// TxRoot is the Merkle root of the block's transaction hashes.
	TxRoot Hash
	// Proposer is the address of the proposing validator.
	Proposer Address
	// ProposerSig is the proposer's PQ signature over the header.
	ProposerSig []byte
}

// Block is a full block: header plus its transactions.
type Block struct {
	Header        BlockHeader
	Transactions  []*Transaction
}

// Marshal encodes the header in canonical form (signature included).
func (h *BlockHeader) Marshal() []byte {
	var b []byte
	b = PutUint32(b, h.Version)
	b = PutUint64(b, h.Height)
	b = PutUint64(b, h.Timestamp)
	b = append(b, h.PrevHash[:]...)
	b = append(b, h.TxRoot[:]...)
	b = append(b, h.Proposer[:]...)
	b = PutBytes(b, h.ProposerSig)
	return b
}

// Unmarshal decodes a header and rejects ambiguous encodings.
func (h *BlockHeader) Unmarshal(data []byte) error {
	r := NewReader(data)
	var err error
	if h.Version, err = r.Uint32(); err != nil {
		return err
	}
	if h.Height, err = r.Uint64(); err != nil {
		return err
	}
	if h.Timestamp, err = r.Uint64(); err != nil {
		return err
	}
	var prev, root, prop []byte
	if prev, err = r.Fixed(HashSize); err != nil {
		return err
	}
	copy(h.PrevHash[:], prev)
	if root, err = r.Fixed(HashSize); err != nil {
		return err
	}
	copy(h.TxRoot[:], root)
	if prop, err = r.Fixed(AddressSize); err != nil {
		return err
	}
	copy(h.Proposer[:], prop)
	if h.ProposerSig, err = r.Bytes(); err != nil {
		return err
	}
	if r.Remaining() != 0 {
		return ErrTrailingBytes
	}
	return nil
}

// Hash returns the canonical hash of the full header.
func (h *BlockHeader) Hash() Hash {
	return HashBytes(h.Marshal())
}

// SignBytes returns the byte string the proposer signs. Like transactions,
// headers sign every field except the signature itself.
func (h *BlockHeader) SignBytes() []byte {
	var b []byte
	b = append(b, "pq-hdr-v1:"...)
	b = append(b, ChainID...)
	b = append(b, 0)
	b = PutUint32(b, h.Version)
	b = PutUint64(b, h.Height)
	b = PutUint64(b, h.Timestamp)
	b = append(b, h.PrevHash[:]...)
	b = append(b, h.TxRoot[:]...)
	b = append(b, h.Proposer[:]...)
	return b
}

// ComputeTxRoot computes the Merkle root over the transaction hashes.
// Blocks with zero transactions use the zero hash as their TxRoot.
func (b *Block) ComputeTxRoot() Hash {
	if len(b.Transactions) == 0 {
		return ZeroHash
	}
	level := make([]byte, 0, len(b.Transactions)*HashSize)
	for _, tx := range b.Transactions {
		h := tx.Hash()
		level = append(level, h[:]...)
	}
	for len(level) > HashSize {
		var next []byte
		for i := 0; i < len(level); i += 2 * HashSize {
			var pair [2 * HashSize]byte
			copy(pair[:HashSize], level[i:i+HashSize])
			if i+HashSize < len(level) {
				copy(pair[HashSize:], level[i+HashSize:i+2*HashSize])
			} else {
				// Odd node: duplicate the last hash (Bitcoin-style).
				copy(pair[HashSize:], level[i:i+HashSize])
			}
			h := HashBytes(pair[:])
			next = append(next, h[:]...)
		}
		level = next
	}
	var root Hash
	copy(root[:], level)
	return root
}
