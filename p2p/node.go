package p2p

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xuda1979/pq-chain/crypto"
	"github.com/xuda1979/pq-chain/protocol"
)

// Timeouts and limits keep the network path safe from slow or hostile
// peers: any peer that stalls or writes garbage is dropped.
const (
	// maxFrame bounds a single on-wire frame body.
	maxFrame = MaxMessageLen

	// handshakeTimeout bounds the exchange of opening handshakes.
	handshakeTimeout = 15 * time.Second

	// readTimeout is applied per frame so a stalled peer is shed.
	readTimeout = 60 * time.Second

	// writeTimeout bounds a single send.
	writeTimeout = 30 * time.Second

	// dialTimeout bounds an outbound connection.
	dialTimeout = 15 * time.Second
)

// ErrDisconnected is returned when the peer closed the session mid-request.
var ErrDisconnected = errors.New("p2p: peer disconnected")

// Identity is a node's signing identity: an ML-DSA keypair whose derived
// address is the node's on-chain address.
type Identity struct {
	Scheme protocol.SignatureScheme
	PK     crypto.PublicKey
	SK     crypto.PrivateKey
}

// NewIdentity derives a fresh ML-DSA identity using suite.
func NewIdentity(suite crypto.Signer) (*Identity, error) {
	pk, sk, err := suite.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &Identity{Scheme: suite.Scheme(), PK: pk, SK: sk}, nil
}

// Address returns the on-chain address of this identity.
func (id *Identity) Address() (protocol.Address, error) {
	return crypto.DeriveAddress(id.Scheme, id.PK)
}

// signHandshake produces the handshake for the given nonce. Scheme and
// PublicKey are set before signing because BytesToSign covers the scheme
// byte; the address and nonce must already be set by the caller.
func (id *Identity) signHandshake(suite crypto.Signer, h *Handshake) error {
	h.Scheme = id.Scheme
	h.PublicKey = id.PK
	sig, err := suite.Sign(id.SK, h.BytesToSign())
	if err != nil {
		return err
	}
	h.Signature = sig
	return nil
}

// Chain is the minimal backend p2p serves; a node supplies headers and
// blocks through this seam (store/state provide them).
type Chain interface {
	Height() uint64
	Headers(start uint64, count uint32) ([]protocol.BlockHeader, error)
	Block(height uint64) (*protocol.Block, error)
}

// Config holds one side's session parameters.
type Config struct {
	// Version of the protocol this node speaks (must equal ProtocolVersion
	// for now; extended negotiation can be added later).
	Version uint8
	// Registry is used to verify peer handshake signatures. It must
	// contain the suite for the node's own identity scheme as well as any
	// peer scheme the operator whitelists.
	Registry *crypto.Registry
	// NewSuite returns a fresh signer for the node identity's scheme.
	NewSuite func() crypto.Signer
	// Chain answers header/block requests.
	Chain Chain
}

// conn wraps a socket with buffered framing.
type conn struct {
	nc net.Conn
	r  *bufio.Reader
	w  *bufio.Writer
	mu sync.Mutex
}

func newConn(nc net.Conn) *conn {
	return &conn{nc: nc, r: bufio.NewReader(nc), w: bufio.NewWriter(nc)}
}

func (c *conn) close() { c.nc.Close() }

// writeRaw sends a length-prefixed blob (handshake stage).
func (c *conn) writeRaw(b []byte) error {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(b)))
	if _, err := c.w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := c.w.Write(b); err != nil {
		return err
	}
	return c.w.Flush()
}

// writeFrame sends a message frame under the session.
func (c *conn) writeFrame(m *Message) error {
	body := m.Marshal()
	if len(body) > maxFrame {
		return fmt.Errorf("p2p: frame %d bytes exceeds %d", len(body), maxFrame)
	}
	c.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeRaw(body)
}

// readRaw reads one length-prefixed blob.
func readRaw(r *bufio.Reader, nc net.Conn, timeout time.Duration) ([]byte, error) {
	nc.SetReadDeadline(time.Now().Add(timeout))
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("p2p: read length: %w", err)
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n == 0 || n > maxFrame {
		return nil, fmt.Errorf("p2p: frame too large: %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("p2p: read body: %w", err)
	}
	return b, nil
}

// readFrame reads one session message.
func (c *conn) readFrame() (*Message, error) {
	raw, err := readRaw(c.r, c.nc, readTimeout)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, err
	}
	var m Message
	if err := m.Unmarshal(raw); err != nil {
		return nil, err
	}
	return &m, nil
}

// Peer is an established, verified connection.
type Peer struct {
	id     protocol.Address
	conn   *conn
	height uint64
}

// ID returns the peer's verified on-chain address.
func (p *Peer) ID() protocol.Address { return p.id }

// Height returns the height the peer announced during handshake.
func (p *Peer) Height() uint64 { return p.height }

// Close ends the session.
func (p *Peer) Close() { p.conn.close() }

// Server accepts and serves inbound connections.
type Server struct {
	cfg  Config
	id   *Identity
	ln   net.Listener
	keep []*Peer
}

// Listen binds addr (e.g. "127.0.0.1:0").
func Listen(cfg Config, id *Identity, addr string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, id: id, ln: ln}, nil
}

// Addr returns the bound address.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Close closes the listener.
func (s *Server) Close() error { return s.ln.Close() }

// Serve accepts peers until ctx is cancelled. Each peer is handled on its
// own goroutine.
func (s *Server) Serve(ctx context.Context) {
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go s.handle(ctx, nc)
	}
}

// handle performs the full server-side session for one inbound conn.
func (s *Server) handle(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	peer, err := s.acceptHandshake(nc)
	if err != nil {
		return
	}
	s.keep = append(s.keep, peer)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		m, err := peer.conn.readFrame()
		if err != nil {
			return
		}
		resp, err := s.serve(m)
		if err != nil {
			return
		}
		if resp != nil {
			if err := peer.conn.writeFrame(resp); err != nil {
				return
			}
		}
	}
}

// serve answers a request from a verified peer.
func (s *Server) serve(m *Message) (*Message, error) {
	switch m.Type {
	case MsgGetHeaders:
		hs, err := s.cfg.Chain.Headers(m.Start, m.Count)
		if err != nil {
			return nil, err
		}
		return &Message{Type: MsgHeaders, Headers: hs}, nil
	case MsgGetBlock:
		b, err := s.cfg.Chain.Block(m.BlockHeight)
		if err != nil {
			return nil, err
		}
		return &Message{Type: MsgBlock, Block: *b}, nil
	default:
		return nil, fmt.Errorf("p2p: unexpected message type %d", m.Type)
	}
}

// acceptHandshake sends ours, then reads and verifies the peer's. Writing
// first on both sides avoids the classic simultaneous-send deadlock.
func (s *Server) acceptHandshake(nc net.Conn) (*Peer, error) {
	c := newConn(nc)
	oh, err := s.ownHandshake()
	if err != nil {
		return nil, err
	}
	if err := c.writeRaw(oh.Marshal()); err != nil {
		return nil, err
	}
	raw, err := readRaw(c.r, nc, handshakeTimeout)
	if err != nil {
		return nil, err
	}
	var ph Handshake
	if err := ph.Unmarshal(raw); err != nil {
		return nil, err
	}
	if err := ph.Verify(s.cfg.Registry); err != nil {
		return nil, err
	}
	return &Peer{id: ph.Address, conn: c, height: ph.Height}, nil
}

// ownHandshake builds and signs this node's handshake with a fresh nonce.
func (s *Server) ownHandshake() (*Handshake, error) {
	addr, err := s.id.Address()
	if err != nil {
		return nil, err
	}
	h := &Handshake{Address: addr, Height: s.cfg.Chain.Height()}
	copy(h.Nonce[:], randomNonce())
	if err := s.id.signHandshake(s.cfg.NewSuite(), h); err != nil {
		return nil, err
	}
	return h, nil
}

// Client dials outbound peers.
type Client struct {
	cfg Config
	id  *Identity
}

// NewClient builds a client with the given identity and config.
func NewClient(cfg Config, id *Identity) *Client {
	return &Client{cfg: cfg, id: id}
}

// Dial connects to addr and performs the client-side handshake, returning
// a verified Peer ready for requests.
func (c *Client) Dial(addr string) (*Peer, error) {
	nc, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, err
	}
	cc := newConn(nc)
	// Both sides write their handshake before reading the peer's, so order
	// here does not matter as long as we don't wait to read first.
	addr2, err := c.id.Address()
	if err != nil {
		nc.Close()
		return nil, err
	}
	oh := &Handshake{Address: addr2, Height: c.cfg.Chain.Height()}
	copy(oh.Nonce[:], randomNonce())
	if err := c.id.signHandshake(c.cfg.NewSuite(), oh); err != nil {
		nc.Close()
		return nil, err
	}
	if err := cc.writeRaw(oh.Marshal()); err != nil {
		nc.Close()
		return nil, err
	}
	raw, err := readRaw(cc.r, nc, handshakeTimeout)
	if err != nil {
		nc.Close()
		return nil, err
	}
	var sh Handshake
	if err := sh.Unmarshal(raw); err != nil {
		nc.Close()
		return nil, err
	}
	if err := sh.Verify(c.cfg.Registry); err != nil {
		nc.Close()
		return nil, err
	}
	return &Peer{id: sh.Address, conn: cc, height: sh.Height}, nil
}

// request sends a request frame and reads the single expected response.
func clientRequest(p *Peer, req *Message, want MessageType) (*Message, error) {
	if err := p.conn.writeFrame(req); err != nil {
		return nil, err
	}
	resp, err := p.conn.readFrame()
	if err != nil {
		return nil, err
	}
	if resp.Type != want {
		return nil, fmt.Errorf("p2p: expected %d, got %d", want, resp.Type)
	}
	return resp, nil
}

// GetHeaders asks peer for headers starting at start, up to count.
func GetHeaders(p *Peer, start uint64, count uint32) ([]protocol.BlockHeader, error) {
	if count == 0 || count > MaxHeadersPerResponse {
		return nil, fmt.Errorf("p2p: bad get-headers count %d", count)
	}
	resp, err := clientRequest(p, &Message{Type: MsgGetHeaders, Start: start, Count: count}, MsgHeaders)
	if err != nil {
		return nil, err
	}
	return resp.Headers, nil
}

// GetBlock asks peer for the block at height.
func GetBlock(p *Peer, height uint64) (*protocol.Block, error) {
	if height < 1 {
		return nil, fmt.Errorf("p2p: bad block height %d", height)
	}
	resp, err := clientRequest(p, &Message{Type: MsgGetBlock, BlockHeight: height}, MsgBlock)
	if err != nil {
		return nil, err
	}
	return &resp.Block, nil
}

func randomNonce() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("p2p: entropy: " + err.Error())
	}
	return b
}
