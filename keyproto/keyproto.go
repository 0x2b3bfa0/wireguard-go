// SPDX-License-Identifier: MIT

// Package keyproto is the wire protocol between a WireGuard host (wireguard-go
// with an exec agent) and an out-of-process static-key agent that holds the
// long-term key (e.g. on a YubiKey).
//
// Transport: newline-delimited JSON (NDJSON) over any io.ReadWriteCloser
// (in practice a Unix-domain socket). Each line is one JSON-RPC 2.0 object.
// NDJSON is chosen over length-prefixed framing so an agent can be written in
// any language with only a JSON library and a line reader. All binary values
// (keys, shared secrets) are standard-base64 strings, so messages never contain
// a raw newline.
//
// Semantics follow JSON-RPC 2.0: requests carry an "id" and expect a matching
// response; a message with a "method" but no "id" is a notification (one-way).
//
// Methods (host -> agent, request/response):
//
//	initialize{version, locator}      -> {version, public_key}
//	shared_secret{peer}               -> {shared_secret}
//
// Notifications (agent -> host, no reply):
//
//	removed                            (the key/card went away; tear down)
//
// The host additionally treats connection close / EOF as removal, so a crashed
// or killed agent also tears the tunnel down.
package keyproto

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Version is the protocol version negotiated in initialize. Bump on any
// incompatible change to message shapes or semantics.
const Version = 1

// Methods.
const (
	MethodInitialize   = "initialize"
	MethodSharedSecret = "shared_secret"
	MethodRemoved      = "removed" // notification, agent -> host
)

// Error codes. JSON-RPC reserves -32768..-32000; -32000..-32099 is the
// "server error" range we use for application errors.
const (
	ErrParse          = -32700 // invalid JSON
	ErrInvalidRequest = -32600 // not a valid request object
	ErrMethodNotFound = -32601
	ErrInvalidParams  = -32602
	ErrInternal       = -32603

	ErrNoKey         = -32001 // locator resolves to no present key/card
	ErrWrongKey      = -32002 // publickey self-check failed
	ErrLocked        = -32003 // PIN/auth required or wrong
	ErrHardware      = -32004 // card/hardware failure
	ErrUnsupported   = -32005 // unsupported version or locator
)

// message is the on-wire JSON-RPC 2.0 object. A single struct covers requests,
// responses, and notifications; unused fields are omitted.
//
// Request:      {jsonrpc, id, method, params}
// Response:     {jsonrpc, id, result}  OR  {jsonrpc, id, error}
// Notification: {jsonrpc, method, params}   (no id)
type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *uint64         `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func (m *message) isNotification() bool { return m.ID == nil && m.Method != "" }
func (m *message) isRequest() bool      { return m.ID != nil && m.Method != "" }
func (m *message) isResponse() bool     { return m.ID != nil && m.Method == "" }

// rpcError is a JSON-RPC 2.0 error object. It implements error.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("keyproto error %d: %s", e.Code, e.Message) }

// Code returns the protocol error code carried by err, or 0 if err is not a
// keyproto wire error.
func Code(err error) int {
	var re *rpcError
	if errors.As(err, &re) {
		return re.Code
	}
	return 0
}

// --- method payloads ---

type InitializeParams struct {
	Version int    `json:"version"`
	Locator string `json:"locator"`
}

type InitializeResult struct {
	Version   int    `json:"version"`
	PublicKey string `json:"public_key"` // standard-base64, 32 bytes
}

type SharedSecretParams struct {
	Peer string `json:"peer"` // standard-base64, 32 bytes
}

type SharedSecretResult struct {
	SharedSecret string `json:"shared_secret"` // standard-base64, 32 bytes
}
