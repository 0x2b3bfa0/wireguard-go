/* SPDX-License-Identifier: MIT
 *
 * Out-of-process static-key agent transport.
 *
 * dialAgent connects to a separate agent process over a Unix socket and returns
 * a StaticKeyAgent that forwards the static-key X25519 DH to it — the ssh-agent
 * model: this process holds no key material and never sees the agent's PIN, it
 * only asks the agent to use the key. It is the resolver behind the UAPI
 * static_key_agent=<socket> line (see SetStaticKeyAgentLocator).
 *
 * Wire protocol — the WireGuard cross-platform UAPI convention itself
 * (https://www.wireguard.com/xplatform/): one operation per connection, request
 * and response are newline-terminated "key=value" lines ending in a blank line,
 * keys are lowercase hex, and the response ends with "errno=0" (non-zero on
 * failure). Two operations:
 *
 *     get=1\n\n                       -> public_key=<hex>\nerrno=0\n\n
 *     shared_secret=1\npeer=<hex>\n\n -> shared_secret=<hex>\nerrno=0\n\n
 *
 * Each SharedSecret dials a fresh connection, exactly as `wg` does for each UAPI
 * operation, so recovery is automatic: if the agent goes away and comes back,
 * the next handshake's dial simply succeeds again — no persistent connection, no
 * reconnect logic. While the agent is gone, SharedSecret errors, the handshake
 * fails, and the link dies at RejectAfterTime; the key being physically
 * necessary for connectivity is the whole point.
 */

package device

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// agentDialTimeout bounds connecting to the agent socket. The agent is local, so
// a short timeout is plenty; a hang here would otherwise stall a handshake.
const agentDialTimeout = 5 * time.Second

// dialAgent resolves a static_key_agent locator (a Unix socket path) into a
// StaticKeyAgent. It fetches the public key once, up front, which both caches
// the identity and fails fast if the agent is unreachable.
func dialAgent(socketPath string) (StaticKeyAgent, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("static_key_agent: empty socket path")
	}
	a := &connAgent{socketPath: socketPath}
	pub, err := a.get()
	if err != nil {
		return nil, err
	}
	a.pub = pub
	return a, nil
}

type connAgent struct {
	socketPath string
	pub        NoisePublicKey
}

// op runs one operation on a fresh connection: send reqLines + a blank line,
// read the "key=value" response up to the blank line, return the parsed fields.
// A non-zero errno is turned into an error.
func (a *connAgent) op(reqLines ...string) (map[string]string, error) {
	conn, err := net.DialTimeout("unix", a.socketPath, agentDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("static_key_agent: dial %s: %w", a.socketPath, err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(strings.Join(reqLines, "\n") + "\n\n")); err != nil {
		return nil, fmt.Errorf("static_key_agent: write: %w", err)
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
		return nil, fmt.Errorf("static_key_agent: read: %w", err)
	}
	if e := resp["errno"]; e != "" && e != "0" {
		return nil, fmt.Errorf("static_key_agent: agent errno=%s %s", e, resp["errmsg"])
	}
	return resp, nil
}

func (a *connAgent) get() (NoisePublicKey, error) {
	resp, err := a.op("get=1")
	if err != nil {
		return NoisePublicKey{}, err
	}
	var pub NoisePublicKey
	if err := pub.FromHex(resp["public_key"]); err != nil {
		return NoisePublicKey{}, fmt.Errorf("static_key_agent: bad public_key: %w", err)
	}
	return pub, nil
}

// SharedSecret asks the agent to compute X25519(static_priv, peer). A wrong or
// absent key surfaces here as an error (or, if the agent now holds a different
// key, as a shared secret that simply won't let peers handshake), so identity is
// pinned the WireGuard-native way without any extra check.
func (a *connAgent) SharedSecret(peer NoisePublicKey) (NoisePublicKey, error) {
	resp, err := a.op("shared_secret=1", "peer="+hex.EncodeToString(peer[:]))
	if err != nil {
		return NoisePublicKey{}, err
	}
	var ss NoisePublicKey
	if err := ss.FromHex(resp["shared_secret"]); err != nil {
		return NoisePublicKey{}, fmt.Errorf("static_key_agent: bad shared_secret: %w", err)
	}
	return ss, nil
}

func (a *connAgent) PublicKey() NoisePublicKey { return a.pub }

var _ StaticKeyAgent = (*connAgent)(nil)
