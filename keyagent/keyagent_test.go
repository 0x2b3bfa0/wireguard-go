// SPDX-License-Identifier: MIT

package keyagent

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// fakeAgent is a restartable software agent speaking the UAPI-style protocol,
// standing in for a card-backed agent so the transport can be tested without
// hardware. It does real X25519, one operation per connection.
type fakeAgent struct {
	path string
	priv *ecdh.PrivateKey
	pub  [32]byte
	ln   net.Listener
}

func startFakeAgent(t *testing.T, path string, priv *ecdh.PrivateKey) *fakeAgent {
	t.Helper()
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeAgent{path: path, priv: priv, ln: ln}
	copy(f.pub[:], priv.PublicKey().Bytes())
	go f.serve()
	return f
}

func (f *fakeAgent) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeAgent) handle(conn net.Conn) {
	defer conn.Close()
	req := map[string]string{}
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		k, v, _ := strings.Cut(line, "=")
		req[k] = v
	}
	switch {
	case req["get"] == "1":
		conn.Write([]byte("public_key=" + hex.EncodeToString(f.pub[:]) + "\nerrno=0\n\n"))
	case req["shared_secret"] == "1":
		peer, err := hex.DecodeString(req["peer"])
		if err != nil {
			conn.Write([]byte("errno=1\nerrmsg=bad peer\n\n"))
			return
		}
		pk, err := ecdh.X25519().NewPublicKey(peer)
		if err != nil {
			conn.Write([]byte("errno=1\nerrmsg=bad point\n\n"))
			return
		}
		ss, err := f.priv.ECDH(pk)
		if err != nil {
			conn.Write([]byte("errno=1\nerrmsg=ecdh failed\n\n"))
			return
		}
		conn.Write([]byte("shared_secret=" + hex.EncodeToString(ss) + "\nerrno=0\n\n"))
	default:
		conn.Write([]byte("errno=1\nerrmsg=unknown op\n\n"))
	}
}

func (f *fakeAgent) stop() { f.ln.Close() }

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

func newKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return k
}

func TestResolveAndSharedSecret(t *testing.T) {
	priv := newKey(t)
	path := shortSocketPath(t)
	agent := startFakeAgent(t, path, priv)
	defer agent.stop()

	a, err := Resolve(path)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if a.PublicKey() != device.NoisePublicKey(agent.pub) {
		t.Fatalf("PublicKey mismatch: %x vs %x", a.PublicKey(), agent.pub)
	}

	peerPriv := newKey(t)
	var peer device.NoisePublicKey
	copy(peer[:], peerPriv.PublicKey().Bytes())

	got, err := a.SharedSecret(peer)
	if err != nil {
		t.Fatalf("SharedSecret: %v", err)
	}
	want, _ := priv.ECDH(peerPriv.PublicKey())
	if got != device.NoisePublicKey(want) {
		t.Fatalf("shared secret mismatch: %x vs %x", got, want)
	}
}

func TestResolveFailsWhenAgentAbsent(t *testing.T) {
	if _, err := Resolve(shortSocketPath(t)); err == nil {
		t.Fatal("expected Resolve to fail with no agent listening")
	}
}

// TestRecoversAfterAgentRestart proves the self-heal: because each call dials a
// fresh connection, losing and restarting the agent needs no reconnect logic.
func TestRecoversAfterAgentRestart(t *testing.T) {
	priv := newKey(t)
	path := shortSocketPath(t)
	agent := startFakeAgent(t, path, priv)

	a, err := Resolve(path)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	peerPriv := newKey(t)
	var peer device.NoisePublicKey
	copy(peer[:], peerPriv.PublicKey().Bytes())

	if _, err := a.SharedSecret(peer); err != nil {
		t.Fatalf("SharedSecret before restart: %v", err)
	}

	// Agent goes away: SharedSecret must error.
	agent.stop()
	if _, err := a.SharedSecret(peer); err == nil {
		t.Fatal("expected error while agent is down")
	}

	// Same key comes back on the same socket: the next call just works.
	agent2 := startFakeAgent(t, path, priv)
	defer agent2.stop()
	// Listener may take a moment to bind after the previous one closed.
	var got device.NoisePublicKey
	for i := 0; i < 50; i++ {
		if got, err = a.SharedSecret(peer); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("did not recover after restart: %v", err)
	}
	want, _ := priv.ECDH(peerPriv.PublicKey())
	if got != device.NoisePublicKey(want) {
		t.Fatalf("shared secret mismatch after restart")
	}
}
