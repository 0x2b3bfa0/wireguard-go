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
// static identity entirely when agent is nil.
func (device *Device) SetStaticKeyAgent(agent StaticKeyAgent) error {
	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	if agent == nil {
		return device.installStaticKeyLocked(nil)
	}
	return device.installStaticKeyLocked(hardwareStaticKey{agent: agent})
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
