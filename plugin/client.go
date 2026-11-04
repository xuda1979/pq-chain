// Package plugin implements the node-to-plugin wire protocol for optional
// accelerated crypto plugins. The protocol is open: any vendor can
// implement a compatible plugin in any language. The node is always the
// client; the plugin is the server.
//
// Handshake (hashicorp go-plugin style):
//
//	1. Node spawns the plugin binary with env PLUGIN_UNIX_SOCKET_DIR set.
//	2. Plugin creates a unix socket "<dir>/plugin.sock", listens, and
//	   prints "PQPLUGIN1|<socket-path>|<abi-version>" on stdout.
//	3. Node verifies ABI version == PluginABIVersion, then speaks
//	   JSON-RPC over the socket.
//
// Every step is bounded by a deadline so a hung or malicious plugin can
// never hang the node.
package plugin

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PluginABIVersion is the wire protocol version. Bump on breaking changes;
// nodes refuse plugins with a mismatched version.
const PluginABIVersion = 1

// HandshakePrefix is the first token of the plugin's stdout handshake.
const HandshakePrefix = "PQPLUGIN1"

// Timeouts. Production nodes must not depend on third-party plugin
// liveness: every plugin interaction is bounded.
const (
	// HandshakeTimeout bounds reading the startup handshake line.
	HandshakeTimeout = 10 * time.Second

	// CallTimeout bounds one JSON-RPC round trip.
	CallTimeout = 30 * time.Second
)

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
	MethodScheme = "scheme"
	MethodKeygen = "generate_key_pair"
	MethodSign   = "sign"
)

// ErrHandshake is returned when the plugin fails the startup handshake.
var ErrHandshake = errors.New("plugin: handshake failed")

// Client is a connected plugin instance. It implements crypto.Signer via
// the adapter in the crypto package. It is safe for concurrent use: RPCs
// are serialized on one connection, each with its own deadline.
type Client struct {
	cmd     *exec.Cmd
	conn    net.Conn
	sockDir string
	// stdinWrite stays open for the plugin's lifetime; closing it on
	// Close signals the plugin (which watches stdin) to exit. If the
	// node process dies without Close, the OS closes the pipe and the
	// plugin still exits — no orphan processes across a fleet.
	stdinWrite io.WriteCloser
	mu         sync.Mutex
	enc        *json.Encoder
	dec        *json.Decoder
	// nextID is only mutated under mu.
	nextID uint64
	// closeOnce makes Close idempotent.
	closeOnce sync.Once
	waitCh    chan struct{}
}

// Dial starts the plugin binary, performs the handshake, and returns a
// connected client. The plugin must be executable and speak ABI version 1.
// On any failure the plugin process is killed and its temp dir removed —
// Dial never leaks a process.
func Dial(binPath string) (*Client, error) {
	sockDir, err := os.MkdirTemp("", "pqplugin-")
	if err != nil {
		return nil, err
	}
	// From here on, any failure must clean up sockDir and the process.
	pluginDied := false
	cleanup := func(cmd *exec.Cmd) {
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
		os.RemoveAll(sockDir)
	}

	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(), "PLUGIN_UNIX_SOCKET_DIR="+sockDir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		os.RemoveAll(sockDir)
		return nil, err
	}
	// stdin is a pipe the node keeps open for the plugin's lifetime. The
	// plugin watches it and exits on EOF — this is the orphan-process
	// defense when the node crashes without calling Close.
	stdinWrite, err := cmd.StdinPipe()
	if err != nil {
		os.RemoveAll(sockDir)
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		os.RemoveAll(sockDir)
		return nil, fmt.Errorf("plugin: start %s: %w", filepath.Base(binPath), err)
	}

	// The plugin owns sockDir once started; the node removes it on Close.
	// If the handshake fails, cleanup does it.
	lineReader := bufio.NewReader(stdout)
	handshakeLine := make(chan string, 1)
	go func() {
		line, err := lineReader.ReadString('\n')
		if err != nil {
			// EOF/err: fall through to timeout below by sending nothing.
			close(handshakeLine)
			return
		}
		handshakeLine <- line
		// Keep draining stdout for the plugin's lifetime: if the plugin
		// logs after the handshake and nobody reads, the OS pipe buffer
		// (64 KiB) fills and the plugin blocks — looking exactly like a
		// hung plugin. Discarded output keeps the child running.
		io.Copy(io.Discard, lineReader)
	}()

	var line string
	select {
	case l, ok := <-handshakeLine:
		if !ok {
			pluginDied = true
		} else {
			line = l
		}
	case <-time.After(HandshakeTimeout):
		cleanup(cmd)
		return nil, fmt.Errorf("%w: no handshake line within %s", ErrHandshake, HandshakeTimeout)
	}
	if pluginDied {
		cleanup(cmd)
		return nil, fmt.Errorf("%w: plugin exited before handshake", ErrHandshake)
	}

	parts := strings.Split(strings.TrimRight(line, "\r\n"), "|")
	if len(parts) != 3 || parts[0] != HandshakePrefix {
		cleanup(cmd)
		return nil, fmt.Errorf("%w: bad handshake %q", ErrHandshake, line)
	}
	sockPath := parts[1]
	// The plugin must create its socket inside the private temp dir the
	// node gave it. Refuse anything else: a hostile or buggy plugin must
	// not be able to point the node at an unrelated system socket.
	if filepath.Dir(sockPath) != sockDir {
		cleanup(cmd)
		return nil, fmt.Errorf("%w: socket path %q outside %s", ErrHandshake, sockPath, sockDir)
	}
	var abi int
	if _, err := fmt.Sscanf(parts[2], "%d", &abi); err != nil {
		cleanup(cmd)
		return nil, fmt.Errorf("%w: bad abi %q", ErrHandshake, parts[2])
	}
	if abi != PluginABIVersion {
		cleanup(cmd)
		return nil, fmt.Errorf("%w: plugin abi %d, node abi %d", ErrHandshake, abi, PluginABIVersion)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		cleanup(cmd)
		return nil, fmt.Errorf("plugin: dial socket: %w", err)
	}

	waitCh := make(chan struct{})
	go func() {
		cmd.Wait()
		close(waitCh)
	}()

	return &Client{
		cmd:        cmd,
		conn:       conn,
		sockDir:    sockDir,
		stdinWrite: stdinWrite,
		enc:        json.NewEncoder(conn),
		dec:        json.NewDecoder(bufio.NewReader(conn)),
		waitCh:     waitCh,
	}, nil
}

// Close terminates the plugin process, closes the connection and removes
// the plugin's temp socket directory. Safe to call multiple times.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		if c.conn != nil {
			c.conn.Close()
		}
		// Closing stdin tells a well-behaved plugin to exit on its own;
		// the Kill below is the backstop for plugins that don't watch.
		if c.stdinWrite != nil {
			c.stdinWrite.Close()
		}
		if c.cmd != nil && c.cmd.Process != nil {
			c.cmd.Process.Kill()
		}
		// cmd.Wait is owned by the goroutine started in Dial.
		<-c.waitCh
		if c.sockDir != "" {
			os.RemoveAll(c.sockDir)
		}
	})
	return nil
}

// call performs one JSON-RPC round trip, serialized with a per-call
// deadline. Concurrent calls queue on the mutex; each sets its own
// conn deadline so one stuck call cannot poison later ones.
func (c *Client) call(method string, params any, result any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.nextID == ^uint64(0) {
		return errors.New("plugin: request id space exhausted")
	}
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
	if err := c.conn.SetDeadline(time.Now().Add(CallTimeout)); err != nil {
		return fmt.Errorf("plugin: %s: %w", method, err)
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
