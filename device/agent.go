/* SPDX-License-Identifier: MIT
 *
 * Static-key abstraction.
 *
 * WireGuard's long-term ("static") private key participates in exactly one
 * cryptographic primitive: the X25519 Diffie-Hellman of the Noise handshake.
 * The device therefore holds its static identity behind the StaticKeyAgent
 * interface rather than as raw bytes, so the DH can be performed either in
 * software (the default) or by an external agent — e.g. one that holds the key
 * on a smartcard or other hardware token — that never discloses the private
 * scalar. Ephemeral DH and the symmetric transport keys stay in software.
 */

package device

// StaticKeyAgent backs the device's static identity. An implementation need only
// perform the static-key X25519 DH and expose the matching public key, never the
// private scalar. The in-memory default is softwareStaticKey; an external caller
// (e.g. an out-of-process agent) provides its own.
type StaticKeyAgent interface {
	// SharedSecret returns X25519(static_priv, peer).
	SharedSecret(peer NoisePublicKey) (NoisePublicKey, error)
	// PublicKey returns the static public key corresponding to static_priv.
	PublicKey() NoisePublicKey
}

// softwareStaticKey is the default StaticKeyAgent: it holds the static private
// key in process memory. It is the only implementation whose key can be
// serialized over UAPI — IpcGetOperation type-asserts to this concrete type, so
// an external agent's key is never exportable.
type softwareStaticKey struct {
	priv NoisePrivateKey
	pub  NoisePublicKey
}

func newSoftwareStaticKey(sk NoisePrivateKey) softwareStaticKey {
	return softwareStaticKey{priv: sk, pub: sk.publicKey()}
}

func (k softwareStaticKey) SharedSecret(peer NoisePublicKey) (NoisePublicKey, error) {
	ss, err := k.priv.sharedSecret(peer)
	return NoisePublicKey(ss), err
}

func (k softwareStaticKey) PublicKey() NoisePublicKey { return k.pub }

// staticSharedSecret performs the static-key X25519 DH via the installed agent.
// It returns errInvalidPublicKey if no identity is configured, or if the DH
// yields an all-zero result — the Noise rejection of an invalid peer point,
// enforced here once for every agent (software or external).
//
// The caller must hold device.staticIdentity's (R)Lock.
func (device *Device) staticSharedSecret(pk NoisePublicKey) ([NoisePublicKeySize]byte, error) {
	agent := device.staticIdentity.key
	if agent == nil {
		return [NoisePublicKeySize]byte{}, errInvalidPublicKey
	}
	ss, err := agent.SharedSecret(pk)
	if err != nil {
		return [NoisePublicKeySize]byte{}, err
	}
	out := [NoisePublicKeySize]byte(ss)
	if isZero(out[:]) {
		return out, errInvalidPublicKey
	}
	return out, nil
}

// SetStaticKeyAgent installs an external static identity, or removes the static
// identity entirely when agent is nil. The caller owns the agent's lifetime; the
// device never closes it. To install an agent from a UAPI locator string instead
// of an object, use SetStaticKeyAgentLocator.
func (device *Device) SetStaticKeyAgent(agent StaticKeyAgent) error {
	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()
	device.installStaticKeyLocked(agent)
	return nil
}

// SetStaticKeyAgentLocator dials the out-of-process agent at locator (a Unix
// socket path) and installs it as the static identity. This is the path used by
// the UAPI static_key_agent line; see keyagent.go for the transport.
//
// The locator is retained verbatim for UAPI get echo-back: it carries no secret
// (just where to reach the agent), so there is nothing to redact — the PIN and
// key live entirely in the agent process.
func (device *Device) SetStaticKeyAgentLocator(locator string) error {
	agent, err := dialAgent(locator)
	if err != nil {
		return err
	}

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()
	device.installStaticKeyLocked(agent)
	device.staticIdentity.agentLocator = locator
	return nil
}

// installStaticKeyLocked swaps in newKey (or nil to clear the identity) and
// performs the per-peer bookkeeping shared by SetPrivateKey, SetStaticKeyAgent,
// and SetStaticKeyAgentLocator: drop peers whose static public key collides with
// the new one, recompute the cached static-static DH, and expire current
// keypairs so fresh handshakes use the new identity.
//
// The caller must hold device.staticIdentity's write lock.
func (device *Device) installStaticKeyLocked(newKey StaticKeyAgent) {
	device.peers.Lock()
	defer device.peers.Unlock()

	// A new identity supersedes any agent locator from a previous install.
	device.staticIdentity.agentLocator = ""

	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	var publicKey NoisePublicKey
	if newKey != nil {
		publicKey = newKey.PublicKey()

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
}
