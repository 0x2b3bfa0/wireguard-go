// SPDX-License-Identifier: MIT

package keyproto

import (
	"errors"
	"net"
	"testing"
	"time"
)

// fakeHandler is an in-memory agent backend for protocol tests.
type fakeHandler struct {
	pub      [32]byte
	initErr  error
	ssFunc   func(peer [32]byte) ([32]byte, error)
	initSeen string
}

func (h *fakeHandler) Initialize(locator string) ([32]byte, error) {
	h.initSeen = locator
	return h.pub, h.initErr
}

func (h *fakeHandler) SharedSecret(peer [32]byte) ([32]byte, error) {
	if h.ssFunc != nil {
		return h.ssFunc(peer)
	}
	// default: echo peer XOR 1 so the result is deterministic and non-zero
	var out [32]byte
	for i := range peer {
		out[i] = peer[i] ^ 1
	}
	return out, nil
}

// pair wires a Serve (agent) to a Client (host) over net.Pipe.
func pair(t *testing.T, h Handler) (*Client, func()) {
	t.Helper()
	hostConn, agentConn := net.Pipe()
	_, wait := Serve(agentConn, h)
	c := NewClient(hostConn)
	cleanup := func() {
		c.Close()
		_ = wait
	}
	return c, cleanup
}

func TestInitializeAndSharedSecret(t *testing.T) {
	h := &fakeHandler{}
	for i := range h.pub {
		h.pub[i] = byte(i + 1)
	}
	c, cleanup := pair(t, h)
	defer cleanup()

	pub, err := c.Initialize("openpgp?slot=decrypt")
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if pub != h.pub {
		t.Fatalf("public key mismatch: got %x want %x", pub, h.pub)
	}
	if h.initSeen != "openpgp?slot=decrypt" {
		t.Fatalf("locator not delivered: %q", h.initSeen)
	}

	var peer [32]byte
	for i := range peer {
		peer[i] = byte(0xA0 + i)
	}
	ss, err := c.SharedSecret(peer)
	if err != nil {
		t.Fatalf("SharedSecret: %v", err)
	}
	var want [32]byte
	for i := range peer {
		want[i] = peer[i] ^ 1
	}
	if ss != want {
		t.Fatalf("shared secret mismatch: got %x want %x", ss, want)
	}
}

func TestInitializeErrorCarriesCode(t *testing.T) {
	h := &fakeHandler{initErr: &CodedError{Code: ErrWrongKey, Err: errors.New("card has a different key")}}
	c, cleanup := pair(t, h)
	defer cleanup()

	_, err := c.Initialize("openpgp")
	if err == nil {
		t.Fatal("expected error")
	}
	if Code(err) != ErrWrongKey {
		t.Fatalf("got code %d, want %d (%v)", Code(err), ErrWrongKey, err)
	}
}

func TestRemovedNotification(t *testing.T) {
	h := &fakeHandler{}
	hostConn, agentConn := net.Pipe()
	pushRemoved, _ := Serve(agentConn, h)
	c := NewClient(hostConn)
	defer c.Close()

	select {
	case <-c.Removed():
		t.Fatal("Removed fired before push")
	default:
	}

	pushRemoved()

	select {
	case <-c.Removed():
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("Removed did not fire after pushRemoved")
	}
}

func TestEOFSignalsRemoved(t *testing.T) {
	h := &fakeHandler{}
	hostConn, agentConn := net.Pipe()
	Serve(agentConn, h)
	c := NewClient(hostConn)

	// Agent side closing the connection must surface as removal on the host.
	agentConn.Close()

	select {
	case <-c.Removed():
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("Removed did not fire on EOF")
	}
}

func TestCallAfterCloseFails(t *testing.T) {
	h := &fakeHandler{}
	hostConn, agentConn := net.Pipe()
	Serve(agentConn, h)
	c := NewClient(hostConn)
	agentConn.Close()

	// Give the read loop a moment to observe EOF and mark closed.
	<-c.Removed()
	if _, err := c.SharedSecret([32]byte{1}); err == nil {
		t.Fatal("expected error calling on a closed connection")
	}
}

func TestConcurrentSharedSecret(t *testing.T) {
	h := &fakeHandler{}
	c, cleanup := pair(t, h)
	defer cleanup()

	const n = 20
	errc := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			var peer [32]byte
			peer[0] = byte(i + 1)
			ss, err := c.SharedSecret(peer)
			if err != nil {
				errc <- err
				return
			}
			var want [32]byte
			want[0] = byte(i+1) ^ 1
			for j := 1; j < 32; j++ {
				want[j] = 0 ^ 1
			}
			if ss != want {
				errc <- errors.New("mismatch")
				return
			}
			errc <- nil
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-errc; err != nil {
			t.Fatalf("concurrent call %d: %v", i, err)
		}
	}
}
