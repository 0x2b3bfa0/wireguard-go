// SPDX-License-Identifier: MIT

package keyagent

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/keyproto"
)

// swHandler is a software keyproto.Handler doing real X25519, standing in for a
// card-backed agent so the connAgent transport/self-heal can be tested without
// hardware.
type swHandler struct {
	priv *ecdh.PrivateKey
	pub  [32]byte
}

func newSWHandler(t *testing.T) *swHandler {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	h := &swHandler{priv: priv}
	copy(h.pub[:], priv.PublicKey().Bytes())
	return h
}

func (h *swHandler) Initialize(string) ([32]byte, error) { return h.pub, nil }

func (h *swHandler) SharedSecret(peer [32]byte) ([32]byte, error) {
	var out [32]byte
	pk, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return out, err
	}
	ss, err := h.priv.ECDH(pk)
	if err != nil {
		return out, err
	}
	copy(out[:], ss)
	return out, nil
}

// fakeAgent is a restartable keyproto server bound to a fixed socket path.
type fakeAgent struct {
	path string
	h    keyproto.Handler
	ln   net.Listener

	mu    sync.Mutex
	conns []net.Conn
}

func startFakeAgent(t *testing.T, path string, h keyproto.Handler) *fakeAgent {
	t.Helper()
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeAgent{path: path, h: h, ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns = append(f.conns, c)
			f.mu.Unlock()
			keyproto.Serve(c, h)
		}
	}()
	return f
}

// stop closes the listener and all live connections (simulating the agent dying
// / the card being pulled, depending on the test).
func (f *fakeAgent) stop() {
	f.ln.Close()
	f.mu.Lock()
	for _, c := range f.conns {
		c.Close()
	}
	f.conns = nil
	f.mu.Unlock()
}

func shortSocketPath(t *testing.T) string {
	t.Helper()
	// macOS limits sun_path to ~104 bytes; t.TempDir() can be long, so use a
	// short MkdirTemp under the system temp dir.
	dir, err := os.MkdirTemp("", "wgk")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}

func TestConnAgentSharedSecretMatchesSoftware(t *testing.T) {
	h := newSWHandler(t)
	path := shortSocketPath(t)
	agent := startFakeAgent(t, path, h)
	defer agent.stop()

	a, err := Resolve(path)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	defer a.(*connAgent).Close()

	if got := a.PublicKey(); got != device.NoisePublicKey(h.pub) {
		t.Fatalf("PublicKey mismatch: got %x want %x", got, h.pub)
	}

	// A random peer key; the agent's result must equal a direct X25519.
	peerPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	var peer device.NoisePublicKey
	copy(peer[:], peerPriv.PublicKey().Bytes())

	got, err := a.SharedSecret(peer)
	if err != nil {
		t.Fatalf("SharedSecret: %v", err)
	}
	want, err := h.SharedSecret([32]byte(peer))
	if err != nil {
		t.Fatalf("reference ECDH: %v", err)
	}
	if got != device.NoisePublicKey(want) {
		t.Fatalf("shared secret mismatch: got %x want %x", got, want)
	}
}

func TestConnAgentSelfHeals(t *testing.T) {
	h := newSWHandler(t)
	path := shortSocketPath(t)
	agent := startFakeAgent(t, path, h)

	a, err := Resolve(path)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	ca := a.(*connAgent)
	defer ca.Close()

	peerPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	var peer device.NoisePublicKey
	copy(peer[:], peerPriv.PublicKey().Bytes())

	if _, err := a.SharedSecret(peer); err != nil {
		t.Fatalf("SharedSecret before removal: %v", err)
	}

	// Kill the agent: Removed() must fire (drives the device's fast teardown),
	// and SharedSecret must then error.
	agent.stop()
	select {
	case <-a.(*connAgent).Removed():
	case <-time.After(2 * time.Second):
		t.Fatal("Removed did not fire after agent died")
	}
	if _, err := a.SharedSecret(peer); err == nil {
		t.Fatal("expected SharedSecret to error while disconnected")
	}

	// Bring the agent back on the same socket; the connAgent must reconnect on
	// its own (redial interval ~1s) and resume serving.
	agent2 := startFakeAgent(t, path, h)
	defer agent2.stop()

	deadline := time.After(8 * time.Second)
	for {
		if _, err := a.SharedSecret(peer); err == nil {
			break // reconnected
		}
		select {
		case <-deadline:
			t.Fatal("connAgent did not self-heal after agent returned")
		case <-time.After(200 * time.Millisecond):
		}
	}
	_ = ca
}
