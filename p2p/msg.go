// Package p2p implements the node-to-node wire protocol: TCP transport
// with canonical length-prefixed framing, an ML-DSA signed handshake, and
// header-first chain sync (GetHeaders/Headers/GetBlock/Block). All
// encodings use the protocol package's strict reader/writer, so the wire
// is identical across every node.
//
// Consensus invariant: p2p never verifies state transitions; it moves
// bytes. Application to consensus state is always the node's job through
// the open-source state machine.
package p2p

import (
	"fmt"

	"github.com/xuda1979/pq-chain/crypto"
	"github.com/xuda1979/pq-chain/protocol"
)

// MessageType identifies a wire message.
type MessageType uint8

const (
	// MsgHello opens a session: node identity + protocol version + best height.
	MsgHello MessageType = 1
	// MsgGetHeaders requests headers starting at Start up to Count.
	MsgGetHeaders MessageType = 2
	// MsgHeaders replies with up to Count consecutive headers.
	MsgHeaders MessageType = 3
	// MsgGetBlock requests the block at Height.
	MsgGetBlock MessageType = 4
	// MsgBlock replies with one full block.
	MsgBlock MessageType = 5
)

// ProtocolVersion is bumped when the wire encoding changes incompatibly.
const ProtocolVersion = 1

// MaxHeadersPerResponse bounds a Headers message (chain-sync pacing).
const MaxHeadersPerResponse = 2000

// MaxMessageLen bounds a single framed message before reading it.
const MaxMessageLen = 1 << 24 // 16 MiB, blocks up to ~1 MiB + sig headroom

// Message is a decoded wire message. Each kind carries only its own fields.
type Message struct {
	Type MessageType
	// Hello fields.
	Version uint8
	Height  uint64
	// GetHeaders fields.
	Start uint64
	Count uint32
	// Headers payload.
	Headers []protocol.BlockHeader
	// GetBlock field.
	BlockHeight uint64
	// Block payload.
	Block protocol.Block
}

// Marshal encodes the message using canonical protocol encoding. Trailing
// bytes are impossible by construction.
func (m *Message) Marshal() []byte {
	var b []byte
	b = append(b, byte(m.Type))
	switch m.Type {
	case MsgHello:
		b = append(b, m.Version)
		b = protocol.PutUint64(b, m.Height)
	case MsgGetHeaders:
		b = protocol.PutUint64(b, m.Start)
		b = protocol.PutUint32(b, m.Count)
	case MsgHeaders:
		b = protocol.PutUint32(b, uint32(len(m.Headers)))
		for i := range m.Headers {
			b = protocol.PutBytes(b, m.Headers[i].Marshal())
		}
	case MsgGetBlock:
		b = protocol.PutUint64(b, m.BlockHeight)
	case MsgBlock:
		b = protocol.PutBytes(b, m.Block.Marshal())
	}
	return b
}

// Unmarshal decodes a message strictly.
func (m *Message) Unmarshal(data []byte) error {
	r := protocol.NewReader(data)
	mt, err := r.Uint8()
	if err != nil {
		return err
	}
	m.Type = MessageType(mt)
	switch m.Type {
	case MsgHello:
		if m.Version, err = r.Uint8(); err != nil {
			return err
		}
		if m.Height, err = r.Uint64(); err != nil {
			return err
		}
	case MsgGetHeaders:
		if m.Start, err = r.Uint64(); err != nil {
			return err
		}
		c, err := r.Uint32()
		if err != nil {
			return err
		}
		if c == 0 || c > MaxHeadersPerResponse {
			return fmt.Errorf("p2p: headers count %d out of range", c)
		}
		m.Count = c
	case MsgHeaders:
		n, err := r.Uint32()
		if err != nil {
			return err
		}
		if n > MaxHeadersPerResponse {
			return fmt.Errorf("p2p: headers %d exceed limit", n)
		}
		m.Headers = make([]protocol.BlockHeader, 0, n)
		for i := uint32(0); i < n; i++ {
			raw, err := r.Bytes()
			if err != nil {
				return err
			}
			var h protocol.BlockHeader
			if err := h.Unmarshal(raw); err != nil {
				return err
			}
			m.Headers = append(m.Headers, h)
		}
	case MsgGetBlock:
		if m.BlockHeight, err = r.Uint64(); err != nil {
			return err
		}
	case MsgBlock:
		raw, err := r.Bytes()
		if err != nil {
			return err
		}
		if err := m.Block.Unmarshal(raw); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unknown message type %d", protocol.ErrInvalidField, uint8(m.Type))
	}
	if r.Remaining() != 0 {
		return protocol.ErrTrailingBytes
	}
	return nil
}

// Handshake carries the peer's session identity: the node address, the
// scheme + public key that derive that address, the current best height,
// a fresh random nonce, and an ML-DSA signature binding all of these to
// the node key. Identity binds address⇔key, so a peer cannot impersonate
// another node's address.
type Handshake struct {
	Address   protocol.Address
	Scheme    protocol.SignatureScheme
	Height    uint64
	Nonce     [32]byte
	PublicKey crypto.PublicKey
	Signature []byte
}

// Marshal encodes the handshake canonically.
func (h *Handshake) Marshal() []byte {
	var b []byte
	b = append(b, h.Address[:]...)
	b = append(b, byte(h.Scheme))
	b = protocol.PutUint64(b, h.Height)
	b = append(b, h.Nonce[:]...)
	b = protocol.PutBytes(b, h.PublicKey)
	b = protocol.PutBytes(b, h.Signature)
	return b
}

// Unmarshal decodes a handshake strictly.
func (h *Handshake) Unmarshal(data []byte) error {
	r := protocol.NewReader(data)
	addr, err := r.Fixed(protocol.AddressSize)
	if err != nil {
		return err
	}
	copy(h.Address[:], addr)
	st, err := r.Uint8()
	if err != nil {
		return err
	}
	h.Scheme = protocol.SignatureScheme(st)
	if h.Height, err = r.Uint64(); err != nil {
		return err
	}
	nonce, err := r.Fixed(32)
	if err != nil {
		return err
	}
	copy(h.Nonce[:], nonce)
	if h.PublicKey, err = r.Bytes(); err != nil {
		return err
	}
	if h.Signature, err = r.Bytes(); err != nil {
		return err
	}
	if r.Remaining() != 0 {
		return protocol.ErrTrailingBytes
	}
	return nil
}

// BytesToSign returns the byte string the handshake signature covers:
// the peer address, scheme, and session nonce. The protocol marker
// prevents replay across versions.
func (h *Handshake) BytesToSign() []byte {
	var b []byte
	b = append(b, "pq-hs-v1:"...)
	b = append(b, protocol.ChainID...)
	b = append(b, byte(ProtocolVersion))
	b = append(b, h.Address[:]...)
	b = append(b, byte(h.Scheme))
	b = append(b, h.Nonce[:]...)
	return b
}

// Verify checks the handshake: the scheme is registered, the public key
// derives to the claimed address, and the signature validates under that
// key over BytesToSign.
func (h *Handshake) Verify(reg *crypto.Registry) error {
	if n, err := crypto.PublicKeySize(h.Scheme); err == nil && len(h.PublicKey) != n {
		return fmt.Errorf("p2p: handshake key size %d, scheme needs %d", len(h.PublicKey), n)
	}
	if err := crypto.ValidatePublicKey(h.Scheme, h.PublicKey); err != nil {
		return err
	}
	derived, err := crypto.DeriveAddress(h.Scheme, h.PublicKey)
	if err != nil {
		return err
	}
	if derived != h.Address {
		return crypto.ErrInvalidKey
	}
	v, err := reg.Verifier(h.Scheme)
	if err != nil {
		return err
	}
	if err := v.Verify(h.PublicKey, h.BytesToSign(), h.Signature); err != nil {
		return err
	}
	return nil
}
