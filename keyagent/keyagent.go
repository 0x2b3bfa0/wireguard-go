/* SPDX-License-Identifier: MIT
 *
 * Package keyagent gives wireguard-go native support for out-of-process static-
 * key agents, in the style of ssh-agent: the WireGuard process holds no key
 * material and links no hardware code — it forwards the static-key X25519 DH
 * over a Unix socket to a separately-running agent that owns the key (e.g. a
 * smartcard). This is the privilege-separation boundary; the WireGuard process
 * never sees the PIN and cannot extract the key, only ask the agent to use it.
 *
 * It registers the "wgk" static_key_agent scheme. Point the device at an agent
 * over UAPI:
 *
 *     static_key_agent=wgk:/run/wg-keyagent.sock
 *     static_key_agent=wgk:/run/wg-keyagent.sock?publickey=<base64>
 *
 * The transport is keyproto (NDJSON + JSON-RPC 2.0), deliberately language-
 * agnostic so agents can be written in anything.
 *
 * The agent connection is SELF-HEALING. When the agent reports the key was
 * removed (its backend hardware was unplugged) or the connection drops, the
 * connAgent signals the device to expire all keypairs immediately (sub-second
 * teardown, via device.RemovalNotifier) and then re-dials the agent in the
 * background. Once the agent is back and holds the same key, DH works again and
 * WireGuard's own handshake timers rebuild the tunnel — no reconfiguration, no
 * supervisor on the WireGuard side. This keeps the runtime to exactly two
 * processes: wireguard-go and the agent.
 */

package keyagent

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/keyproto"
)

const (
	// dialTimeout bounds connecting to the agent socket. The agent is local, so
	// a short timeout is plenty; a hang here would otherwise stall UAPI config.
	dialTimeout = 5 * time.Second
	// reconnectInterval paces background re-dial attempts after the agent goes
	// away (its backend hardware removed, or the agent process restarting).
	reconnectInterval = 1 * time.Second
)

type connAgent struct {
	socketPath string
	pub        device.NoisePublicKey

	mu     sync.Mutex
	client *keyproto.Client // current connection; nil while disconnected

	removed chan struct{} // device watches this (RemovalNotifier); one send per loss
	done    chan struct{} // closed by Close to stop the supervisor
	closed  bool
}

// Resolve is a device.StaticKeyAgentResolver: it builds a self-healing agent
// connection from a locator. The locator is simply the path to the agent's Unix
// socket:
//
//	/run/wg-keyagent.sock
//
// It carries no secret — the PIN and the key live entirely in the agent
// process. Wire it into wireguard-go with
// device.SetStaticKeyAgentResolver(keyagent.Resolve); the UAPI line is then
// static_key_agent=/run/wg-keyagent.sock.
//
// Identity is pinned the WireGuard-native way: peers list this device's public
// key, so a wrong/absent key simply fails to handshake. The connection also
// refuses any identity that changes across a reconnect (see dialAndInit), so a
// swapped token is rejected rather than silently adopted.
func Resolve(locator string) (device.StaticKeyAgent, error) {
	if locator == "" {
		return nil, fmt.Errorf("keyagent: empty socket path")
	}

	a := &connAgent{
		socketPath: locator,
		removed:    make(chan struct{}, 1),
		done:       make(chan struct{}),
	}

	// Initial connection is synchronous: fail fast if the agent isn't reachable,
	// so a bad UAPI config is rejected immediately.
	client, pub, err := a.dialAndInit()
	if err != nil {
		return nil, err
	}
	a.pub = pub
	a.client = client

	go a.supervise(client)
	return a, nil
}

// dialAndInit opens a connection, runs initialize, and (on reconnect) verifies
// the recovered identity equals the one we first saw.
func (a *connAgent) dialAndInit() (*keyproto.Client, device.NoisePublicKey, error) {
	var zero device.NoisePublicKey
	conn, err := net.DialTimeout("unix", a.socketPath, dialTimeout)
	if err != nil {
		return nil, zero, fmt.Errorf("dial key agent at %s: %w", a.socketPath, err)
	}
	client := keyproto.NewClient(conn)

	// The agent already knows its own card + PIN; the locator carries no secret.
	// The empty string is reserved for future multi-identity selection.
	pubArr, err := client.Initialize("")
	if err != nil {
		client.Close()
		return nil, zero, fmt.Errorf("initialize key agent: %w", err)
	}
	var pub device.NoisePublicKey
	copy(pub[:], pubArr[:])

	// On reconnect, a.pub is already set; the recovered identity must match it,
	// so a different token swapped in while the agent restarted is refused.
	var unset device.NoisePublicKey
	if a.pub != unset && a.pub != pub {
		client.Close()
		return nil, zero, fmt.Errorf("agent public key changed across reconnect; refusing")
	}
	return client, pub, nil
}

// supervise watches the live connection; on loss it signals the device (fast
// teardown) and re-dials until the agent returns or Close is called.
func (a *connAgent) supervise(client *keyproto.Client) {
	for {
		select {
		case <-a.done:
			client.Close()
			return
		case <-client.Removed():
			// Connection lost (removal notification or EOF).
		}

		a.setClient(nil)
		a.notifyRemoved() // device expires keypairs now (sub-second teardown)
		client.Close()

		next := a.redial()
		if next == nil {
			return // Close was called during re-dial
		}
		a.setClient(next)
		client = next
		log.Printf("wgk: reconnected to key agent at %s", a.socketPath)
	}
}

// redial retries dial+initialize at reconnectInterval until it succeeds or Close
// is called (returns nil).
func (a *connAgent) redial() *keyproto.Client {
	for {
		select {
		case <-a.done:
			return nil
		case <-time.After(reconnectInterval):
		}
		client, _, err := a.dialAndInit()
		if err != nil {
			continue // agent not back yet (or wrong key); keep waiting
		}
		return client
	}
}

func (a *connAgent) setClient(c *keyproto.Client) {
	a.mu.Lock()
	a.client = c
	a.mu.Unlock()
}

func (a *connAgent) getClient() *keyproto.Client {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.client
}

func (a *connAgent) notifyRemoved() {
	select {
	case a.removed <- struct{}{}:
	default: // a removal is already pending; coalesce
	}
}

// SharedSecret forwards X25519(static_priv, peer) to the agent. While
// disconnected it errors, which fails the handshake — exactly the desired
// behavior when the key is unavailable.
func (a *connAgent) SharedSecret(peer device.NoisePublicKey) (device.NoisePublicKey, error) {
	c := a.getClient()
	if c == nil {
		return device.NoisePublicKey{}, fmt.Errorf("wgk: key agent disconnected")
	}
	ss, err := c.SharedSecret([32]byte(peer))
	if err != nil {
		return device.NoisePublicKey{}, err
	}
	return device.NoisePublicKey(ss), nil
}

// PublicKey returns the static public key reported by the agent. It is stable
// across reconnects (dialAndInit refuses an identity that changed).
func (a *connAgent) PublicKey() device.NoisePublicKey { return a.pub }

// Removed implements device.RemovalNotifier: it fires once each time the agent
// connection is lost, so the device can expire keypairs for fast teardown.
func (a *connAgent) Removed() <-chan struct{} { return a.removed }

// Close stops the supervisor and drops the connection. Idempotent.
func (a *connAgent) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	close(a.done)
	a.mu.Unlock()
	return nil
}

// Compile-time checks.
var (
	_ device.StaticKeyAgent  = (*connAgent)(nil)
	_ device.RemovalNotifier = (*connAgent)(nil)
)
