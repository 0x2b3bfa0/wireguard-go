/* SPDX-License-Identifier: MIT
 *
 * Static-key abstraction.
 *
 * WireGuard's long-term ("static") private key participates in exactly one
 * cryptographic primitive: the X25519 Diffie-Hellman of the Noise handshake.
 * The device therefore holds its static identity behind the staticKey
 * interface rather than as raw bytes, so the DH can be performed either in
 * software (the default) or by an external agent — e.g. a smartcard or other
 * hardware token — that never discloses the private scalar. Ephemeral DH and
 * the symmetric transport keys are unaffected and stay in software.
 */

package device

import (
	"fmt"
	"io"
)

// staticKey is the device's long-term identity, abstracted over where the
// private key lives. The static private key is used only for DH, so an
// implementation need expose just that operation, the matching public key, and
// — when the key is held in software — a way to read the raw private bytes back
// out. Hardware-backed implementations report themselves non-exportable.
//
// This is the package-internal abstraction; external callers supply hardware
// via the exported StaticKeyAgent interface, adapted by hardwareStaticKey.
type staticKey interface {
	// sharedSecret returns X25519(static_priv, peer). It returns
	// errInvalidPublicKey if the result is all-zero (an invalid peer point).
	sharedSecret(peer NoisePublicKey) ([NoisePublicKeySize]byte, error)
	// publicKey returns the static public key.
	publicKey() NoisePublicKey
	// privateKey returns the raw private key when it is held in software, with
	// ok == true. Hardware-backed keys cannot disclose it and return ok ==
	// false. The value (not pointer) form hands back a copy the caller owns,
	// avoiding aliasing the stored secret.
	privateKey() (NoisePrivateKey, bool)
}

// softwareStaticKey holds the static private key in process memory (the default).
type softwareStaticKey struct {
	priv NoisePrivateKey
	pub  NoisePublicKey
}

func newSoftwareStaticKey(sk NoisePrivateKey) softwareStaticKey {
	return softwareStaticKey{priv: sk, pub: sk.publicKey()}
}

func (k softwareStaticKey) sharedSecret(peer NoisePublicKey) ([NoisePublicKeySize]byte, error) {
	return k.priv.sharedSecret(peer)
}

func (k softwareStaticKey) publicKey() NoisePublicKey { return k.pub }

func (k softwareStaticKey) privateKey() (NoisePrivateKey, bool) { return k.priv, true }

// StaticKeyAgent is the public contract a caller implements to back the device's
// static key with hardware. The agent performs the static-key X25519 DH without
// revealing the private key.
type StaticKeyAgent interface {
	// SharedSecret returns X25519(static_priv, peer).
	SharedSecret(peer NoisePublicKey) (NoisePublicKey, error)
	// PublicKey returns the static public key corresponding to static_priv.
	PublicKey() NoisePublicKey
}

// hardwareStaticKey adapts an external StaticKeyAgent to the internal staticKey
// interface. The private key lives in the agent's hardware and is never
// exportable.
type hardwareStaticKey struct {
	agent StaticKeyAgent
}

func (k hardwareStaticKey) sharedSecret(peer NoisePublicKey) (ss [NoisePublicKeySize]byte, err error) {
	out, err := k.agent.SharedSecret(peer)
	if err != nil {
		return ss, err
	}
	ss = [NoisePublicKeySize]byte(out)
	if isZero(ss[:]) {
		return ss, errInvalidPublicKey
	}
	return ss, nil
}

func (k hardwareStaticKey) publicKey() NoisePublicKey { return k.agent.PublicKey() }

func (k hardwareStaticKey) privateKey() (NoisePrivateKey, bool) { return NoisePrivateKey{}, false }

// staticSharedSecret performs the static-key X25519 DH via whatever staticKey
// is installed (software or hardware). It returns errInvalidPublicKey if no
// identity is configured.
//
// The caller must hold device.staticIdentity's (R)Lock.
func (device *Device) staticSharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte, err error) {
	key := device.staticIdentity.key
	if key == nil {
		return ss, errInvalidPublicKey
	}
	return key.sharedSecret(pk)
}

// SetStaticKeyAgent installs a hardware-backed static identity, or removes the
// static identity entirely when agent is nil. The caller retains ownership of
// the agent (it is not closed by the device); for device-owned agents resolved
// from a locator, use SetStaticKeyAgentLocator.
func (device *Device) SetStaticKeyAgent(agent StaticKeyAgent) error {
	var newKey staticKey
	if agent != nil {
		newKey = hardwareStaticKey{agent: agent}
	}

	device.staticIdentity.Lock()
	displaced := device.installStaticKeyLocked(newKey)
	device.staticIdentity.Unlock()

	// Close the displaced device-owned agent after unlocking (its Close may block).
	closeAgent(displaced)
	return nil
}

// StaticKeyAgentResolver turns a static_key_agent locator (the value of the UAPI
// static_key_agent= line) into a StaticKeyAgent. wireguard-go knows nothing about
// how agents are reached or what a locator means; the embedding binary supplies a
// concrete resolver (e.g. keyagent.Resolve, which dials a Unix socket).
type StaticKeyAgentResolver func(locator string) (StaticKeyAgent, error)

// SetStaticKeyAgentResolver installs the resolver used by SetStaticKeyAgentLocator
// (and thus the UAPI static_key_agent line). It is per-device, holds no global
// state, and is typically set once during setup, before serving UAPI. Without a
// resolver, a static_key_agent line is rejected.
func (device *Device) SetStaticKeyAgentResolver(resolve StaticKeyAgentResolver) {
	device.staticIdentity.Lock()
	device.staticIdentity.agentResolver = resolve
	device.staticIdentity.Unlock()
}

// SetStaticKeyAgentLocator resolves locator via the configured resolver and
// installs the resulting agent as the static identity. The agent is
// device-owned: it is closed (if it implements io.Closer) when the identity is
// later replaced or the device is closed. This is the path used by the UAPI
// static_key_agent line.
//
// The locator is retained verbatim for UAPI get echo-back: it carries no secret
// (just where to reach the agent), so there is nothing to redact — the PIN and
// key live entirely in the agent process.
func (device *Device) SetStaticKeyAgentLocator(locator string) error {
	device.staticIdentity.RLock()
	resolve := device.staticIdentity.agentResolver
	device.staticIdentity.RUnlock()
	if resolve == nil {
		return fmt.Errorf("no static_key_agent resolver configured")
	}

	agent, err := resolve(locator)
	if err != nil {
		return fmt.Errorf("static_key_agent: %w", err)
	}

	device.staticIdentity.Lock()
	displaced := device.installStaticKeyLocked(hardwareStaticKey{agent: agent})
	device.staticIdentity.agentLocator = locator
	device.staticIdentity.Unlock()

	// Close the displaced device-owned agent after unlocking (its Close may block).
	closeAgent(displaced)
	return nil
}

// closeAgent closes an agent that implements io.Closer; otherwise a no-op.
func closeAgent(agent StaticKeyAgent) {
	if c, ok := agent.(io.Closer); ok {
		_ = c.Close()
	}
}

// installStaticKeyLocked swaps in newKey (or nil to clear the identity) and
// performs the per-peer bookkeeping shared by SetPrivateKey and
// SetStaticKeyAgent: drop peers whose static public key collides with our new
// one, recompute the cached static-static DH, and expire current keypairs so
// fresh handshakes use the new identity.
//
// If the previous identity was a device-owned (locator-resolved) agent, it is
// returned as displaced so the caller can Close it AFTER releasing the locks —
// an agent's Close may block (it releases hardware/closes a socket), and must
// not run under staticIdentity's write lock + peers lock or it would freeze the
// whole device. Returns nil if there was nothing device-owned to close.
//
// The caller must hold device.staticIdentity's write lock, and must call
// closeAgent on the returned value once unlocked.
func (device *Device) installStaticKeyLocked(newKey staticKey) (displaced StaticKeyAgent) {
	device.peers.Lock()
	defer device.peers.Unlock()

	// Hand back a previously device-owned agent for the caller to close later.
	if device.staticIdentity.agentLocator != "" {
		if hw, ok := device.staticIdentity.key.(hardwareStaticKey); ok {
			displaced = hw.agent
		}
		device.staticIdentity.agentLocator = ""
	}

	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	var publicKey NoisePublicKey
	if newKey != nil {
		publicKey = newKey.publicKey()

		// remove peers with matching public keys
		for key, peer := range device.peers.keyMap {
			if peer.handshake.remoteStatic.Equals(publicKey) {
				peer.handshake.mutex.RUnlock()
				removePeerLocked(device, peer, key)
				peer.handshake.mutex.RLock()
			}
		}
	}

	// update key material
	device.staticIdentity.key = newKey
	device.staticIdentity.publicKey = publicKey
	device.cookieChecker.Init(publicKey)

	// recompute the cached static-static DH for every peer under the new identity
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		if newKey != nil {
			handshake.precomputedStaticStatic, _ = device.staticSharedSecret(handshake.remoteStatic)
		} else {
			handshake.precomputedStaticStatic = [NoisePublicKeySize]byte{}
		}
	}

	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	// expire keypairs only after releasing the handshake read locks
	// (ExpireCurrentKeypairs takes the handshake write lock)
	for _, peer := range device.peers.keyMap {
		peer.ExpireCurrentKeypairs()
	}
	return displaced
}
