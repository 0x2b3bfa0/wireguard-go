// SPDX-License-Identifier: MIT

package device

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
)

// fakeAgent is a restartable software agent speaking the UAPI-style protocol,
// standing in for a card-backed agent so the transport can be tested without
// hardware. It does real X25519 and holds one or more keys, selected by key=,
// one operation per connection.
type fakeAgent struct {
	path string
	keys map[string]*ecdh.PrivateKey // hex(pub) -> private key
	ln   net.Listener
}

func startFakeAgent(t *testing.T, path string, privs ...*ecdh.PrivateKey) *fakeAgent {
	t.Helper()
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeAgent{path: path, keys: map[string]*ecdh.PrivateKey{}, ln: ln}
	for _, p := range privs {
		f.keys[hex.EncodeToString(p.PublicKey().Bytes())] = p
	}
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

// sole returns the only key's hex public key, or "" if there are zero or many.
func (f *fakeAgent) sole() string {
	if len(f.keys) != 1 {
		return ""
	}
	for h := range f.keys {
		return h
	}
	return ""
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

	// Resolve which key the request selects: explicit key=, else the sole key.
	want := req["key"]
	if want == "" {
		want = f.sole()
	}

	switch {
	case req["get"] == "1":
		if want == "" || f.keys[want] == nil {
			conn.Write([]byte("errno=1\nerrmsg=no such key (or ambiguous)\n\n"))
			return
		}
		conn.Write([]byte("public_key=" + want + "\nerrno=0\n\n"))
	case req["shared_secret"] == "1":
		priv := f.keys[want]
		if priv == nil {
			conn.Write([]byte("errno=1\nerrmsg=no such key\n\n"))
			return
		}
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
		ss, err := priv.ECDH(pk)
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

func newAgentKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return k
}

func hexPub(p *ecdh.PrivateKey) string { return hex.EncodeToString(p.PublicKey().Bytes()) }

// checkDH asserts the agent computes the same X25519 as software for a fresh peer.
func checkDH(t *testing.T, a StaticKeyAgent, priv *ecdh.PrivateKey) {
	t.Helper()
	peerPriv := newAgentKey(t)
	var peer NoisePublicKey
	copy(peer[:], peerPriv.PublicKey().Bytes())
	got, err := a.SharedSecret(peer)
	if err != nil {
		t.Fatalf("SharedSecret: %v", err)
	}
	want, _ := priv.ECDH(peerPriv.PublicKey())
	if got != NoisePublicKey(want) {
		t.Fatalf("shared secret mismatch: %x vs %x", got, want)
	}
}

// the locator must declare publickey=.
func TestDialAgentRequiresPublickey(t *testing.T) {
	priv := newAgentKey(t)
	path := shortSocketPath(t)
	agent := startFakeAgent(t, path, priv)
	defer agent.stop()

	if _, err := dialAgent(path); err == nil {
		t.Fatal("expected error: locator without publickey=")
	}
}

// publickey= selects the identity (and the card) among the agent's keys.
func TestDialAgentSelectsKey(t *testing.T) {
	k1, k2 := newAgentKey(t), newAgentKey(t)
	path := shortSocketPath(t)
	agent := startFakeAgent(t, path, k1, k2)
	defer agent.stop()

	a, err := dialAgent(path + "?publickey=" + hexPub(k2))
	if err != nil {
		t.Fatalf("dialAgent: %v", err)
	}
	var wantPub NoisePublicKey
	copy(wantPub[:], k2.PublicKey().Bytes())
	if a.PublicKey() != wantPub {
		t.Fatalf("selected identity mismatch")
	}
	checkDH(t, a, k2)
}

// pinning a key the agent does not hold fails fast.
func TestDialAgentKeyAbsent(t *testing.T) {
	path := shortSocketPath(t)
	agent := startFakeAgent(t, path, newAgentKey(t))
	defer agent.stop()

	absent := hexPub(newAgentKey(t))
	if _, err := dialAgent(path + "?publickey=" + absent); err == nil {
		t.Fatal("expected error pinning a key the agent does not hold")
	}
}

func TestDialAgentFailsWhenAgentAbsent(t *testing.T) {
	pub := hexPub(newAgentKey(t))
	if _, err := dialAgent(shortSocketPath(t) + "?publickey=" + pub); err == nil {
		t.Fatal("expected dialAgent to fail with no agent listening")
	}
}

// TestAgentRecoversAfterRestart proves the self-heal: because each call dials a
// fresh connection, losing and restarting the agent needs no reconnect logic.
func TestAgentRecoversAfterRestart(t *testing.T) {
	priv := newAgentKey(t)
	path := shortSocketPath(t)
	agent := startFakeAgent(t, path, priv)

	a, err := dialAgent(path + "?publickey=" + hexPub(priv))
	if err != nil {
		t.Fatalf("dialAgent: %v", err)
	}
	checkDH(t, a, priv)

	// Agent goes away: SharedSecret must error.
	agent.stop()
	var peer NoisePublicKey
	copy(peer[:], newAgentKey(t).PublicKey().Bytes())
	if _, err := a.SharedSecret(peer); err == nil {
		t.Fatal("expected error while agent is down")
	}

	// Same key comes back on the same socket: the next call just works.
	agent2 := startFakeAgent(t, path, priv)
	defer agent2.stop()
	for i := 0; i < 50; i++ {
		if _, err = a.SharedSecret(peer); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("did not recover after restart: %v", err)
	}
}
