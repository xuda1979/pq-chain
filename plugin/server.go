package plugin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
)

// Serve runs the plugin side of the protocol: create the socket, print the
// handshake, then serve JSON-RPC until stdin/stdout close. handler
// implements the actual crypto; this function only does transport. Vendors
// writing closed-source plugins implement Handler and link this open-source
// transport, so the wire protocol is always compatible.
func Serve(handler Handler) error {
	sockDir := os.Getenv("PLUGIN_UNIX_SOCKET_DIR")
	if sockDir == "" {
		return fmt.Errorf("plugin: PLUGIN_UNIX_SOCKET_DIR not set; must be launched by a node")
	}
	sockPath := filepath.Join(sockDir, "plugin.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("plugin: listen: %w", err)
	}
	defer os.Remove(sockPath)

	// Handshake: node reads this line from our stdout.
	fmt.Printf("%s|%s|%d\n", HandshakePrefix, sockPath, PluginABIVersion)
	os.Stdout.Sync()

	conn, err := ln.Accept()
	if err != nil {
		return fmt.Errorf("plugin: accept: %w", err)
	}
	defer conn.Close()

	dec := json.NewDecoder(bufio.NewReader(conn))
	enc := json.NewEncoder(conn)
	for {
		var req Request
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("plugin: read: %w", err)
		}
		resp := Response{ID: req.ID}
		result, err := dispatch(handler, req)
		if err != nil {
			resp.Error = err.Error()
		} else {
			raw, err := json.Marshal(result)
			if err != nil {
				resp.Error = err.Error()
			} else {
				resp.Result = raw
			}
		}
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("plugin: write: %w", err)
		}
	}
}

// dispatch routes one request to the handler.
func dispatch(h Handler, req Request) (any, error) {
	switch req.Method {
	case MethodScheme:
		return SchemeResult{Scheme: uint8(h.Scheme())}, nil
	case MethodKeygen:
		pk, sk, err := h.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		return KeyPairResult{PublicKey: pk, PrivateKey: sk}, nil
	case MethodSign:
		var p SignParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, fmt.Errorf("bad sign params: %w", err)
			}
		}
		sig, err := h.Sign(p.PrivateKey, p.Message)
		if err != nil {
			return nil, err
		}
		return SignResult{Signature: sig}, nil
	default:
		return nil, fmt.Errorf("unknown method %q", req.Method)
	}
}

// Handler is what a plugin binary must implement. This is the seam between
// the open transport and proprietary crypto implementations.
type Handler interface {
	Scheme() uint8
	GenerateKeyPair() (publicKey, privateKey []byte, err error)
	Sign(privateKey, message []byte) (signature []byte, err error)
}
