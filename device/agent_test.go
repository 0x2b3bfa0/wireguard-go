/* SPDX-License-Identifier: MIT
 *
 * Tests for the static-key abstraction (agent.go).
 *
 * These use a *software* StaticKeyAgent that holds the private key in memory.
 * That defeats the security purpose (hardware custody) but exercises exactly
 * the code path a hardware agent — e.g. a YubiKey OpenPGP cv25519 key — drives:
 * the device's static identity is a hardwareStaticKey, so every static-key DH
 * routes through StaticKeyAgent.SharedSecret instead of an in-memory private key. If a full
 * Noise handshake completes with the agent in place, the seam is correct.
 */

package device

import (
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// softwareKeyAgent implements StaticKeyAgent by performing the X25519 DH in
// software. Stand-in for a hardware agent in tests.
type softwareKeyAgent struct {
	priv NoisePrivateKey
	pub  NoisePublicKey
}

func newSoftwareKeyAgent(t *testing.T) *softwareKeyAgent {
	t.Helper()
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &softwareKeyAgent{priv: sk, pub: sk.publicKey()}
}

func (a *softwareKeyAgent) SharedSecret(peer NoisePublicKey) (NoisePublicKey, error) {
	ss, err := a.priv.sharedSecret(peer)
	return NoisePublicKey(ss), err
}

func (a *softwareKeyAgent) PublicKey() NoisePublicKey { return a.pub }

// newTestDevice builds a bare device with a discard logger, mirroring
// randDevice's construction without setting a private key.
func newTestDevice(t *testing.T) *Device {
	t.Helper()
	tun := tuntest.NewChannelTUN()
	return NewDevice(tun.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
}

// agentDevice builds a device whose static key is held by a software agent,
// mirroring randDevice but via SetStaticKeyAgent.
func agentDevice(t *testing.T) *Device {
	t.Helper()
	device := newTestDevice(t)
	if err := device.SetStaticKeyAgent(newSoftwareKeyAgent(t)); err != nil {
		t.Fatal(err)
	}
	return device
}

// TestStaticKeyAgentEquivalence checks that routing through the agent yields the
// same shared secret as the in-memory private key would, for random peers.
func TestStaticKeyAgentEquivalence(t *testing.T) {
	agent := newSoftwareKeyAgent(t)
	device := newTestDevice(t)
	if err := device.SetStaticKeyAgent(agent); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		peerSK, err := newPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		peerPK := peerSK.publicKey()

		device.staticIdentity.RLock()
		viaAgent, err := device.staticSharedSecret(peerPK)
		device.staticIdentity.RUnlock()
		if err != nil {
			t.Fatalf("agent DH failed: %v", err)
		}

		viaSoftware, err := agent.priv.sharedSecret(peerPK)
		if err != nil {
			t.Fatalf("software DH failed: %v", err)
		}

		if viaAgent != viaSoftware {
			t.Fatalf("mismatch at %d:\n agent=%x\n  soft=%x", i, viaAgent, viaSoftware)
		}
	}
}

// TestExportableGuard verifies that a hardware-backed key is never exportable
// (so UAPI get cannot leak it), while a software key is.
func TestExportableGuard(t *testing.T) {
	dev := newTestDevice(t)

	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.SetPrivateKey(sk); err != nil {
		t.Fatal(err)
	}
	dev.staticIdentity.RLock()
	got, ok := dev.staticIdentity.key.privateKey()
	dev.staticIdentity.RUnlock()
	if !ok || !got.Equals(sk) {
		t.Fatalf("software key should be exportable and equal; ok=%v", ok)
	}

	if err := dev.SetStaticKeyAgent(newSoftwareKeyAgent(t)); err != nil {
		t.Fatal(err)
	}
	dev.staticIdentity.RLock()
	_, ok = dev.staticIdentity.key.privateKey()
	dev.staticIdentity.RUnlock()
	if ok {
		t.Fatal("hardware-backed key must not be exportable")
	}
}

// TestStaticConfigured verifies the gate that replaced privateKey.IsZero().
func TestStaticConfigured(t *testing.T) {
	device := newTestDevice(t)

	device.staticIdentity.RLock()
	configured := device.staticConfigured()
	device.staticIdentity.RUnlock()
	if configured {
		t.Fatal("fresh device reports configured")
	}

	if err := device.SetStaticKeyAgent(newSoftwareKeyAgent(t)); err != nil {
		t.Fatal(err)
	}
	device.staticIdentity.RLock()
	configured = device.staticConfigured()
	device.staticIdentity.RUnlock()
	if !configured {
		t.Fatal("device with agent reports not configured")
	}

	if err := device.SetStaticKeyAgent(nil); err != nil {
		t.Fatal(err)
	}
	device.staticIdentity.RLock()
	configured = device.staticConfigured()
	device.staticIdentity.RUnlock()
	if configured {
		t.Fatal("device after agent removal reports configured")
	}
}

// TestNoiseHandshakeWithAgent runs the full Noise handshake with the static key
// held by an agent on the initiator, the responder, or both. Reuses the
// upstream testNoiseHandshake driver.
func TestNoiseHandshakeWithAgent(t *testing.T) {
	t.Run("agent-initiator", func(t *testing.T) {
		testNoiseHandshake(t, agentDevice(t), randDevice(t))
	})
	t.Run("agent-responder", func(t *testing.T) {
		testNoiseHandshake(t, randDevice(t), agentDevice(t))
	})
	t.Run("both-agent", func(t *testing.T) {
		testNoiseHandshake(t, agentDevice(t), agentDevice(t))
	})
}
