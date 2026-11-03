// Package plugin implements the node-to-plugin wire protocol for optional
// accelerated crypto plugins. The protocol is open: any vendor can
// implement a compatible plugin in any language. The node is always the
// gRPC-style client; the plugin is the server.
//
// Handshake (hashicorp go-plugin style):
//
//	1. Node spawns the plugin binary with env PLUGIN_UNIX_SOCKET_DIR set.
//	2. Plugin creates a unix socket "<dir>/plugin.sock", listens, and
//	   prints "PQPLUGIN1|<socket-path>|<abi-version>" on stdout.
//	3. Node verifies ABI version == PluginABIVersion, then speaks
//	   length-prefixed JSON-RPC over the socket.
package plugin

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
)

// PluginABIVersion is the wire protocol version. Bump on breaking changes;
// nodes refuse plugins with a mismatched version.
const PluginABIVersion = 1

// HandshakePrefix is the first token of the plugin's stdout handshake.
const HandshakePrefix = "PQPLUGIN1"

// Request is a single call from node to plugin.
type Request struct {
	// ID is a caller-chosen correlation number echoed in responses.
	ID uint64 `json:"id"`
	// Method selects the RPC: "scheme", "generate_key_pair", or "sign".
	Method string `json:"method"`
	// Params carries method-specific arguments.
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is the plugin's reply.
type Response struct {
	// ID echoes the request ID.
	ID uint64 `json:"id"`
	// Error is empty on success; otherwise a human-readable message.
	Error string `json:"error,omitempty"`
	// Result carries method-specific return values.
	Result json.RawMessage `json:"result,omitempty"`
}

// RPC method names.
const (
	MethodScheme  = "scheme"
	MethodKeygen  = "generate_key_pair"
	MethodSign    = "sign"
)

// ErrHandshake is returned when the plugin fails the startup handshake.
var ErrHandshake = errors.New("plugin: handshake failed")

// Client is a connected plugin instance. It implements crypto.Signer via
// the adapter in the crypto package.
type Client struct {
	cmd    *exec.Cmd
	conn   net.Conn
	enc    *json.Encoder
	dec    *json.Decoder
	nextID uint64
}

// Dial starts the plugin binary, performs the handshake, and returns a
// connected client. The plugin must be executable and speak ABI version 1.
func Dial(binPath string) (*Client, error) {
	sockDir, err := os.MkdirTemp("", "pqplugin-")
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(), "PLUGIN_UNIX_SOCKET_DIR="+sockDir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("plugin: start %s: %w", filepath.Base(binPath), err)
	}

	// Read handshake line with a hard deadline-ish bounded read.
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("%w: no handshake line: %v", ErrHandshake, err)
	}
	var prefix, sockPath string
	var abi int
	if _, err := fmt.Sscanf(line, "%s", &prefix); err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("%w: bad handshake %q", ErrHandshake, line)
	}
	// Format: PQPLUGIN1|<path>|<abi>
	parts := splitHandshake(line)
	if len(parts) != 3 || parts[0] != HandshakePrefix {
		cmd.Process.Kill()
		return nil, fmt.Errorf("%w: bad handshake %q", ErrHandshake, line)
	}
	prefix = parts[0]
	sockPath = parts[1]
	if _, err := fmt.Sscanf(parts[2], "%d", &abi); err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("%w: bad abi %q", ErrHandshake, parts[2])
	}
	if abi != PluginABIVersion {
		cmd.Process.Kill()
		return nil, fmt.Errorf("%w: plugin abi %d, node abi %d", ErrHandshake, abi, PluginABIVersion)
	}
	_ = prefix

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("plugin: dial socket: %w", err)
	}
	return &Client{
		cmd:  cmd,
		conn: conn,
		enc:  json.NewEncoder(conn),
		dec:  json.NewDecoder(conn),
	}, nil
}

func splitHandshake(line string) []string {
	line = trimSpaceNewline(line)
	var parts []string
	start := 0
	for i := 0; i <= len(line); i++ {
		if i == len(line) || line[i] == '|' {
			parts = append(parts, line[start:i])
			start = i + 1
		}
	}
	return parts
}

func trimSpaceNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// Close terminates the plugin process and connection.
func (c *Client) Close() error {
	if c.conn != nil {
		c.conn.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		return c.cmd.Process.Kill()
	}
	return nil
}

// call performs one JSON-RPC round trip.
func (c *Client) call(method string, params any, result any) error {
	c.nextID++
	id := c.nextID
	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		rawParams = b
	}
	if err := c.enc.Encode(Request{ID: id, Method: method, Params: rawParams}); err != nil {
		return fmt.Errorf("plugin: write %s: %w", method, err)
	}
	var resp Response
	if err := c.dec.Decode(&resp); err != nil {
		return fmt.Errorf("plugin: read %s: %w", method, err)
	}
	if resp.ID != id {
		return fmt.Errorf("plugin: %s response id mismatch", method)
	}
	if resp.Error != "" {
		return fmt.Errorf("plugin: %s: %s", method, resp.Error)
	}
	if result != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, result); err != nil {
			return fmt.Errorf("plugin: %s result: %w", method, err)
		}
	}
	return nil
}

// SchemeResult is the reply to the "scheme" RPC.
type SchemeResult struct {
	Scheme uint8 `json:"scheme"`
}

// Scheme asks the plugin which on-chain signature scheme it accelerates.
func (c *Client) Scheme() (uint8, error) {
	var res SchemeResult
	if err := c.call(MethodScheme, nil, &res); err != nil {
		return 0, err
	}
	return res.Scheme, nil
}

// KeyPairResult is the reply to "generate_key_pair".
type KeyPairResult struct {
	PublicKey  []byte `json:"public_key"`
	PrivateKey []byte `json:"private_key"`
}

// GenerateKeyPair asks the plugin to create a key pair for its scheme.
func (c *Client) GenerateKeyPair() ([]byte, []byte, error) {
	var res KeyPairResult
	if err := c.call(MethodKeygen, nil, &res); err != nil {
		return nil, nil, err
	}
	return res.PublicKey, res.PrivateKey, nil
}

// SignParams is the argument to "sign".
type SignParams struct {
	PrivateKey []byte `json:"private_key"`
	Message    []byte `json:"message"`
}

// SignResult is the reply to "sign".
type SignResult struct {
	Signature []byte `json:"signature"`
}

// Sign asks the plugin to sign msg with sk.
func (c *Client) Sign(sk, msg []byte) ([]byte, error) {
	var res SignResult
	if err := c.call(MethodSign, SignParams{PrivateKey: sk, Message: msg}, &res); err != nil {
		return nil, err
	}
	return res.Signature, nil
}

// WriteUint64 appends v little-endian (kept for future binary framing).
func WriteUint64(b []byte, v uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return append(b, buf[:]...)
}

var _ = io.EOF
