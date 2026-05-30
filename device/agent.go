/* SPDX-License-Identifier: MIT
 *
 * Static-key abstraction.
 *
 * WireGuard's long-term ("static") private key participates in exactly one
 * cryptographic primitive: the X25519 Diffie-Hellman of the Noise handshake.
 * The device therefore holds its static identity behind the staticKey
 * interface rather than as raw bytes, so the DH can be performed either in
 * software (the default) or by external hardware — e.g. a YubiKey OpenPGP
 * cv25519 key — that never discloses the private scalar. Ephemeral DH and the
 * symmetric transport keys are unaffected and stay in software.
 */

package device

import (
	"fmt"
	"io"
	"strings"
	"sync"
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

// softwareStaticKey holds the static private key in process memory. This is the
// default and behaves exactly as upstream wireguard-go did.
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

// staticConfigured reports whether a static identity is installed.
//
// The caller must hold device.staticIdentity's (R)Lock.
func (device *Device) staticConfigured() bool {
	return device.staticIdentity.key != nil
}

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
// from a URI, use SetStaticKeyAgentURI.
func (device *Device) SetStaticKeyAgent(agent StaticKeyAgent) error {
	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	if agent == nil {
		return device.installStaticKeyLocked(nil)
	}
	return device.installStaticKeyLocked(hardwareStaticKey{agent: agent})
}

// StaticKeyAgentConstructor builds a StaticKeyAgent from a locator string (the
// part of a static_key_agent URI after the scheme). It is registered against a
// scheme name with RegisterStaticKeyAgentScheme.
type StaticKeyAgentConstructor func(locator string) (StaticKeyAgent, error)

var (
	agentSchemesMu sync.RWMutex
	agentSchemes   = map[string]StaticKeyAgentConstructor{}
)

// RegisterStaticKeyAgentScheme registers a constructor for static_key_agent
// URIs of the form "<scheme>:<locator>". This is how an embedding application
// plugs in a hardware backend (e.g. a smartcard) without the device package
// depending on it. Registering the same scheme twice overwrites the previous
// constructor. Typically called from an init function or main.
func RegisterStaticKeyAgentScheme(scheme string, ctor StaticKeyAgentConstructor) {
	agentSchemesMu.Lock()
	defer agentSchemesMu.Unlock()
	agentSchemes[scheme] = ctor
}

func lookupStaticKeyAgentScheme(scheme string) (StaticKeyAgentConstructor, bool) {
	agentSchemesMu.RLock()
	defer agentSchemesMu.RUnlock()
	ctor, ok := agentSchemes[scheme]
	return ctor, ok
}

// ResolveStaticKeyAgentURI resolves a "<scheme>:<locator>" URI against the
// registered agent schemes and constructs the agent, WITHOUT installing it. The
// caller owns the returned agent (and must Close it if applicable). This allows
// resolving/validating a startup identity before other setup (e.g. before
// opening a TUN), so misconfiguration fails fast.
func ResolveStaticKeyAgentURI(uri string) (StaticKeyAgent, error) {
	scheme, locator, ok := strings.Cut(uri, ":")
	if !ok || scheme == "" {
		return nil, fmt.Errorf("invalid static_key_agent URI %q: want scheme:locator", uri)
	}

	ctor, ok := lookupStaticKeyAgentScheme(scheme)
	if !ok {
		return nil, fmt.Errorf("unknown static_key_agent scheme %q", scheme)
	}

	agent, err := ctor(locator)
	if err != nil {
		return nil, fmt.Errorf("static_key_agent %q: %w", scheme, err)
	}
	return agent, nil
}

// SetStaticKeyAgentURI resolves a "<scheme>:<locator>" URI against the
// registered agent schemes, constructs the agent, and installs it as the static
// identity. The resulting agent is device-owned: it is closed (if it implements
// io.Closer) when the identity is later replaced or the device is closed. This
// is the path used by the UAPI static_key_agent line.
func (device *Device) SetStaticKeyAgentURI(uri string) error {
	agent, err := ResolveStaticKeyAgentURI(uri)
	if err != nil {
		return err
	}

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	if err := device.installStaticKeyLocked(hardwareStaticKey{agent: agent}); err != nil {
		closeAgent(agent)
		return err
	}
	device.staticIdentity.agentURI = uri
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
// The caller must hold device.staticIdentity's write lock.
func (device *Device) installStaticKeyLocked(newKey staticKey) error {
	device.peers.Lock()
	defer device.peers.Unlock()

	// Close a previously device-owned (URI-resolved) agent before replacing it.
	if device.staticIdentity.agentURI != "" {
		if hw, ok := device.staticIdentity.key.(hardwareStaticKey); ok {
			closeAgent(hw.agent)
		}
		device.staticIdentity.agentURI = ""
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

	// do static-static DH pre-computations
	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		if newKey != nil {
			handshake.precomputedStaticStatic, _ = device.staticSharedSecret(handshake.remoteStatic)
		} else {
			handshake.precomputedStaticStatic = [NoisePublicKeySize]byte{}
		}
		expiredPeers = append(expiredPeers, peer)
	}

	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}
	return nil
}
