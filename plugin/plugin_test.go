package plugin

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
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

// TestProtocolConcurrentClients hammers one plugin connection from many
// goroutines, as a busy node would: RPCs are serialized internally, and
// every response must correlate to its own request (no crossed streams,
// no deadlocks under queueing).
func TestProtocolConcurrentClients(t *testing.T) {
	if os.Getenv("BE_PLUGIN_CHILD") == "1" {
		if err := Serve(&testHandler{scheme: 2}); err != nil {
			t.Fatal(err)
		}
		return
	}

	dir := t.TempDir()
	wrapper := filepath.Join(dir, "wrap.sh")
	_ = os.WriteFile(wrapper, []byte("#!/bin/sh\nBE_PLUGIN_CHILD=1 exec \""+os.Args[0]+"\" -test.run=TestProtocolConcurrentClients\n"), 0o755)

	client, err := Dial(wrapper)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	const workers = 16
	const perWorker = 25
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				sk := []byte{byte(w), byte(i)}
				msg := []byte{byte(w), byte(i), 'l', 'o', 'a', 'd'}
				sig, err := client.Sign(sk, msg)
				if err != nil {
					errs <- fmt.Errorf("worker %d call %d: %w", w, i, err)
					return
				}
				want := make([]byte, 64)
				for k := range want {
					want[k] = sk[k%len(sk)] ^ msg[k%len(msg)]
				}
				if !bytes.Equal(sig, want) {
					errs <- fmt.Errorf("worker %d call %d: crossed response", w, i)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestPluginExitsWhenNodeDiesBeforeDial pins the orphan defense for the
// worst case: the node spawns the plugin, then crashes (or is killed)
// before ever dialing the socket. The plugin must notice the stdin EOF
// and exit by itself — a fleet must never accumulate zombie plugins
// behind crashed nodes. The child is spawned directly (no wrapper): the
// test holds the stdin pipe, closes it to simulate node death, and
// waits for the child to exit.
func TestPluginExitsWhenNodeDiesBeforeDial(t *testing.T) {
	if os.Getenv("BE_PLUGIN_CHILD") == "1" {
		if err := Serve(&testHandler{scheme: 2}); err != nil {
			t.Fatal(err)
		}
		return
	}

	dir := t.TempDir()
	sockDir := filepath.Join(dir, "sock")
	if err := os.Mkdir(sockDir, 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestPluginExitsWhenNodeDiesBeforeDial")
	cmd.Env = append(os.Environ(),
		"BE_PLUGIN_CHILD=1",
		"PLUGIN_UNIX_SOCKET_DIR="+sockDir,
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Simulate node death before dial: close stdin without connecting.
	// The plugin is blocked in Accept; only the stdin watch can save it.
	_ = stdin.Close()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		// Plugin exited on its own: orphan defense works.
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatal("plugin still running 15s after node death: orphaned")
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
