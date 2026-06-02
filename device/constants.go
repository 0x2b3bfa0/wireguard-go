/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"time"
)

/* Specification constants */

// NOTE: Timer constants customized for hardware-bound connectivity.
// When the static key lives on an external token, the goal is that unplugging it
// drops the link within a couple of seconds and it cannot be re-established
// without the token. To that end the whole timer family is rescaled (not just
// two values — they are interdependent, see receive.go:61 and the RekeyTimeout
// rate-limit in send.go) to: proactive rekey at 500ms, hard keypair rejection at
// 2s. This is the sole teardown mechanism: with no token, handshakes fail and
// the current keypair is rejected at RejectAfterTime.
//
// CONSEQUENCES:
//   - NON-INTEROPERABLE with stock WireGuard: both peers must run this build
//     with identical constants.
//   - Aggressive: every rekey triggers an agent DH (~85ms on a smartcard).
//     Validate that 500ms rekey is stable under that latency before trusting.
const (
	RekeyAfterMessages      = (1 << 60)
	RejectAfterMessages     = (1 << 64) - (1 << 13) - 1
	RekeyAfterTime          = time.Millisecond * 500
	RekeyAttemptTime        = time.Millisecond * 1600
	RekeyTimeout            = time.Millisecond * 400
	MaxTimerHandshakes      = 1600 / 400 /* RekeyAttemptTime / RekeyTimeout */
	RekeyTimeoutJitterMaxMs = 100
	RejectAfterTime         = time.Second * 2
	KeepaliveTimeout        = time.Millisecond * 400
	CookieRefreshTime       = time.Second * 120
	HandshakeInitationRate  = time.Second / 50
	PaddingMultiple         = 16
)

const (
	MinMessageSize = MessageKeepaliveSize                  // minimum size of transport message (keepalive)
	MaxMessageSize = MaxSegmentSize                        // maximum size of transport message
	MaxContentSize = MaxSegmentSize - MessageTransportSize // maximum size of transport message content
)

/* Implementation constants */

const (
	UnderLoadAfterTime = time.Second // how long does the device remain under load after detected
	MaxPeers           = 1 << 16     // maximum number of configured peers
)
