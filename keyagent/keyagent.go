/* SPDX-License-Identifier: MIT
 *
 * Package keyagent gives wireguard-go native support for out-of-process static-
 * key agents, in the style of ssh-agent: the WireGuard process holds no key
 * material and links no hardware code — it forwards the static-key X25519 DH
 * over a Unix socket to a separately-running agent that owns the key (e.g. a
 * smartcard). This is the privilege-separation boundary; the WireGuard process
 * never sees the PIN and cannot extract the key, only ask the agent to use it.
 *
 * Wire protocol — the WireGuard cross-platform UAPI convention itself
 * (https://www.wireguard.com/xplatform/), reused rather than reinvented: one
 * operation per connection, request and response are newline-terminated
 * "key=value" lines ending in a blank line, keys are lowercase hex, and the
 * response ends with "errno=0" on success (non-zero on failure). Two operations:
 *
 *     get=1\n\n                          -> public_key=<hex>\nerrno=0\n\n
 *     shared_secret=1\npeer=<hex>\n\n    -> shared_secret=<hex>\nerrno=0\n\n
 *
 * Each SharedSecret dials a fresh connection, exactly as `wg` does for each UAPI
 * operation. That makes recovery automatic: if the agent goes away and comes
 * back, the next handshake's dial simply succeeds again — no persistent
 * connection, no reconnect logic. While the agent is gone, SharedSecret errors,
 * the handshake fails, and the link dies at RejectAfterTime; the key being
 * physically necessary for connectivity is the whole point.
 */

package keyagent

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// dialTimeout bounds connecting to the agent socket. The agent is local, so a
// short timeout is plenty; a hang here would otherwise stall a handshake.
const dialTimeout = 5 * time.Second

// Resolve is a device.StaticKeyAgentResolver. The locator is the path to the
// agent's Unix socket; it carries no secret (the PIN and key live in the agent).
// Wire it in with device.SetStaticKeyAgentResolver(keyagent.Resolve); the UAPI
// line is then static_key_agent=/run/wg-keyagent.sock.
func Resolve(locator string) (device.StaticKeyAgent, error) {
	if locator == "" {
		return nil, fmt.Errorf("keyagent: empty socket path")
	}
	a := &connAgent{socketPath: locator}
	// Fetch the public key once, up front: this both caches the identity and
	// fails fast if the agent is unreachable, so a bad UAPI config is rejected
	// immediately.
	pub, err := a.get()
	if err != nil {
		return nil, err
	}
	a.pub = pub
	return a, nil
}

type connAgent struct {
	socketPath string
	pub        device.NoisePublicKey
}

// op runs one UAPI-style operation on a fresh connection: it sends reqLines
// followed by a blank line, reads the "key=value" response up to the blank line,
// and returns the parsed fields. A non-zero errno is turned into an error.
func (a *connAgent) op(reqLines ...string) (map[string]string, error) {
	conn, err := net.DialTimeout("unix", a.socketPath, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("keyagent: dial %s: %w", a.socketPath, err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(strings.Join(reqLines, "\n") + "\n\n")); err != nil {
		return nil, fmt.Errorf("keyagent: write: %w", err)
	}

	resp := make(map[string]string)
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // blank line terminates the operation
		}
		k, v, _ := strings.Cut(line, "=")
		resp[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("keyagent: read: %w", err)
	}
	if e := resp["errno"]; e != "" && e != "0" {
		return nil, fmt.Errorf("keyagent: agent errno=%s %s", e, resp["errmsg"])
	}
	return resp, nil
}

func (a *connAgent) get() (device.NoisePublicKey, error) {
	resp, err := a.op("get=1")
	if err != nil {
		return device.NoisePublicKey{}, err
	}
	return decodeKey(resp["public_key"])
}

// SharedSecret asks the agent to compute X25519(static_priv, peer). A wrong or
// absent key surfaces here as an error (or, if the agent now holds a different
// key, as a shared secret that simply won't let peers handshake), so identity is
// pinned the WireGuard-native way without any extra check.
func (a *connAgent) SharedSecret(peer device.NoisePublicKey) (device.NoisePublicKey, error) {
	resp, err := a.op("shared_secret=1", "peer="+hex.EncodeToString(peer[:]))
	if err != nil {
		return device.NoisePublicKey{}, err
	}
	return decodeKey(resp["shared_secret"])
}

func (a *connAgent) PublicKey() device.NoisePublicKey { return a.pub }

// decodeKey parses a lowercase-hex 32-byte key, as used by UAPI.
func decodeKey(s string) (device.NoisePublicKey, error) {
	var k device.NoisePublicKey
	b, err := hex.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("keyagent: invalid hex key: %w", err)
	}
	if len(b) != len(k) {
		return k, fmt.Errorf("keyagent: key is %d bytes, want %d", len(b), len(k))
	}
	copy(k[:], b)
	return k, nil
}

var _ device.StaticKeyAgent = (*connAgent)(nil)
