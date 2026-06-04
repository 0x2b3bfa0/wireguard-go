/* SPDX-License-Identifier: MIT
 *
 * Out-of-process static-key agent transport.
 *
 * dialAgent connects to a separate agent process over a Unix socket and returns
 * a StaticKeyAgent that forwards the static-key X25519 DH to it — the ssh-agent
 * model: this process holds no key material and never sees the agent's PIN, it
 * only asks the agent to use the key. It is the resolver behind the UAPI
 * static_key_agent=<locator> line (see SetStaticKeyAgentLocator).
 *
 * The locator is a Unix socket path with a required public-key selector:
 *
 *     /run/wg-keyagent.sock?publickey=<hex>
 *
 * The public key is the identity handle. It declares this interface's identity
 * (the agent-mode analog of a private_key: the operator states which key is
 * theirs, by its public half, since the private half is on the token) and tells
 * the agent which token to use. The host confirms the agent holds it, then sends
 * it as key= on every operation. It is required so the config fully declares the
 * identity — like private_key, you never omit it and let the runtime guess.
 *
 * Wire protocol — the WireGuard cross-platform UAPI convention itself
 * (https://www.wireguard.com/xplatform/): one operation per connection, request
 * and response are newline-terminated "key=value" lines ending in a blank line,
 * keys are lowercase hex, and the response ends with "errno=0" (non-zero on
 * failure). Two operations, both naming the identity via key=:
 *
 *     get=1\nkey=<hex>\n\n                       -> public_key=<hex>\nerrno=0\n\n
 *     shared_secret=1\nkey=<hex>\npeer=<hex>\n\n -> shared_secret=<hex>\nerrno=0\n\n
 *
 * Each operation dials a fresh connection, exactly as `wg` does for each UAPI
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
	"net/url"
	"strings"
	"time"
)

// agentDialTimeout bounds connecting to the agent socket. The agent is local, so
// a short timeout is plenty; a hang here would otherwise stall a handshake.
const agentDialTimeout = 5 * time.Second

// dialAgent resolves a static_key_agent locator into a StaticKeyAgent. The
// locator must declare the interface's identity via publickey= (the agent-mode
// analog of a private_key — the operator states which key is theirs by its
// public half, since the private half is on the token). dialAgent then confirms,
// via get, that the agent currently holds that key, so a wrong socket or absent
// token fails at config time rather than silently never handshaking.
func dialAgent(locator string) (StaticKeyAgent, error) {
	socketPath, query, _ := strings.Cut(locator, "?")
	if socketPath == "" {
		return nil, fmt.Errorf("static_key_agent: empty socket path")
	}
	vals, err := url.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("static_key_agent: bad locator query: %w", err)
	}
	hexPub := vals.Get("publickey")
	if hexPub == "" {
		return nil, fmt.Errorf("static_key_agent: publickey= is required (this interface's public key, in hex)")
	}

	a := &connAgent{socketPath: socketPath}
	if err := a.pub.FromHex(hexPub); err != nil {
		return nil, fmt.Errorf("static_key_agent: bad publickey: %w", err)
	}
	if err := a.confirm(); err != nil {
		return nil, err
	}
	return a, nil
}

// confirm asks the agent for our key and checks it answers with the same key,
// proving the token is present and reachable.
func (a *connAgent) confirm() error {
	resp, err := a.op("get=1", "key="+hex.EncodeToString(a.pub[:]))
	if err != nil {
		return err
	}
	var got NoisePublicKey
	if err := got.FromHex(resp["public_key"]); err != nil {
		return fmt.Errorf("static_key_agent: bad public_key from agent: %w", err)
	}
	if got != a.pub {
		return fmt.Errorf("static_key_agent: agent returned a different key than requested")
	}
	return nil
}

type connAgent struct {
	socketPath string
	pub        NoisePublicKey // our identity, also the key= selector we send
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

// SharedSecret asks the agent to compute X25519(static_priv, peer) with our key.
func (a *connAgent) SharedSecret(peer NoisePublicKey) (NoisePublicKey, error) {
	resp, err := a.op(
		"shared_secret=1",
		"key="+hex.EncodeToString(a.pub[:]),
		"peer="+hex.EncodeToString(peer[:]),
	)
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
