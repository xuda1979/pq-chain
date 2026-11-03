package plugin

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// testHandler is an in-memory fake plugin implementation.
type testHandler struct {
	scheme uint8
	// panicOnSign makes Sign panic, to test panic isolation.
	panicOnSign bool
}

func (h *testHandler) Scheme() uint8 { return h.scheme }

func (h *testHandler) GenerateKeyPair() ([]byte, []byte, error) {
	pk := make([]byte, 32)
	sk := make([]byte, 32)
	if _, err := rand.Read(pk); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(sk); err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

func (h *testHandler) Sign(privateKey, message []byte) ([]byte, error) {
	if h.panicOnSign {
		panic("vendor bug: sign exploded")
	}
	// Deterministic fake "signature": privateKey XOR message, repeated.
	out := make([]byte, 64)
	for i := range out {
		out[i] = privateKey[i%len(privateKey)] ^ message[i%len(message)]
	}
	return out, nil
}

// TestProtocolRoundTrip runs a real plugin subprocess: Serve in a child
// process, Dial from the test, and exercise the full RPC surface.
func TestProtocolRoundTrip(t *testing.T) {
	if os.Getenv("BE_PLUGIN_CHILD") == "1" {
		// Child mode: act as the plugin and exit when done.
		if err := Serve(&testHandler{scheme: 2}); err != nil {
			t.Fatal(err)
		}
		return
	}

	// Spawn ourselves as the plugin: the wrapper sets the child-mode env
	// var and re-runs this test binary with only this test.
	dir := t.TempDir()
	wrapper := filepath.Join(dir, "wrap.sh")
	_ = os.WriteFile(wrapper, []byte("#!/bin/sh\nBE_PLUGIN_CHILD=1 exec \""+os.Args[0]+"\" -test.run=TestProtocolRoundTrip\n"), 0o755)

	client, err := Dial(wrapper)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	scheme, err := client.Scheme()
	if err != nil {
		t.Fatalf("scheme: %v", err)
	}
	if scheme != 2 {
		t.Fatalf("scheme = %d, want 2", scheme)
	}

	pk, sk, err := client.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if len(pk) != 32 || len(sk) != 32 {
		t.Fatalf("key sizes: pk=%d sk=%d", len(pk), len(sk))
	}

	msg := []byte("post-quantum message")
	sig, err := client.Sign(sk, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	want := make([]byte, 64)
	for i := range want {
		want[i] = sk[i%len(sk)] ^ msg[i%len(msg)]
	}
	if !bytes.Equal(sig, want) {
		t.Fatal("fake signature mismatch")
	}
}

// TestProtocolRoundTripPanicIsolation runs a plugin whose Sign panics: the
// panic must surface as an RPC error, and the plugin process must survive
// to serve later calls (a dead plugin takes the node's accelerated
// signing down with it).
func TestProtocolRoundTripPanicIsolation(t *testing.T) {
	if os.Getenv("BE_PLUGIN_CHILD_PANIC") == "1" {
		if err := Serve(&testHandler{scheme: 2, panicOnSign: true}); err != nil {
			t.Fatal(err)
		}
		return
	}

	dir := t.TempDir()
	wrapper := filepath.Join(dir, "wrap.sh")
	_ = os.WriteFile(wrapper, []byte("#!/bin/sh\nBE_PLUGIN_CHILD_PANIC=1 exec \""+os.Args[0]+"\" -test.run=TestProtocolRoundTripPanicIsolation\n"), 0o755)

	client, err := Dial(wrapper)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Scheme still works (panics are per-request, not fatal).
	scheme, err := client.Scheme()
	if err != nil {
		t.Fatalf("scheme: %v", err)
	}
	if scheme != 2 {
		t.Fatalf("scheme = %d, want 2", scheme)
	}

	// Sign returns an RPC error, not a dead connection.
	if _, err := client.Sign([]byte("k"), []byte("m")); err == nil {
		t.Fatal("panicking sign reported success")
	}

	// The plugin is still alive: scheme works again.
	if _, err := client.Scheme(); err != nil {
		t.Fatalf("plugin died after panic: %v", err)
	}
}

// TestRequestResponseJSON pins the JSON encoding of the wire types so the
// ABI stays stable across releases.
func TestRequestResponseJSON(t *testing.T) {
	req := Request{ID: 7, Method: MethodSign, Params: json.RawMessage(`{"private_key":"AA==","message":"Ag=="}`)}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"method":"sign"`)) {
		t.Fatalf("unexpected encoding: %s", b)
	}
	var resp Response
	if err := json.Unmarshal([]byte(`{"id":7,"result":{"signature":"Aw=="}}`), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != 7 || len(resp.Result) == 0 {
		t.Fatalf("unexpected decode: %+v", resp)
	}
}
