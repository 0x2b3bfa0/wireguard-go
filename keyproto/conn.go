// SPDX-License-Identifier: MIT

package keyproto

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// maxLineBytes bounds a single NDJSON message to defend against a peer sending
// an unbounded line. A keyproto message is a few hundred bytes; 64 KiB is ample.
const maxLineBytes = 64 * 1024

// ---------- agent side ----------

// Handler is implemented by the agent backend (e.g. the YubiKey). Its methods
// are invoked by Serve when the host sends the corresponding request. They run
// on Serve's single read goroutine, so calls are serialized (a smartcard
// serializes anyway); a Handler need not be safe for concurrent use.
type Handler interface {
	// Initialize opens the identity named by locator and returns its 32-byte
	// X25519 public key. Called once at the start of a session.
	Initialize(locator string) (pub [32]byte, err error)
	// SharedSecret returns X25519(static_priv, peer) computed on the hardware.
	SharedSecret(peer [32]byte) (ss [32]byte, err error)
}

// Serve reads requests from rw and dispatches them to h until rw closes or a
// fatal protocol error occurs. The returned removed channel lets the handler
// (or the agent's own card watcher) push a "removed" notification to the host:
// closing or sending on it is not the mechanism — instead the caller calls the
// returned PushRemoved func. Serve owns rw and closes it on return.
//
// Serve returns nil on a clean EOF (host hung up) and a non-nil error on a
// protocol/transport failure.
func Serve(rw io.ReadWriteCloser, h Handler) (pushRemoved func(), wait func() error) {
	s := &server{
		rw:   rw,
		h:    h,
		enc:  json.NewEncoder(rw),
		done: make(chan struct{}),
	}
	go func() {
		s.err = s.loop()
		close(s.done)
	}()
	pushRemoved = func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return
		}
		// Best-effort notification; a write error just means the host is gone,
		// which it will also detect via EOF.
		_ = s.enc.Encode(&message{JSONRPC: "2.0", Method: MethodRemoved})
	}
	wait = func() error {
		<-s.done
		return s.err
	}
	return pushRemoved, wait
}

type server struct {
	rw   io.ReadWriteCloser
	h    Handler
	enc  *json.Encoder
	done chan struct{}
	err  error

	mu     sync.Mutex // serializes writes (loop responses vs pushRemoved)
	closed bool
}

func (s *server) loop() error {
	defer func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.rw.Close()
	}()

	sc := bufio.NewScanner(s.rw)
	sc.Buffer(make([]byte, 0, 4096), maxLineBytes)
	for sc.Scan() {
		var m message
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			s.respondError(nil, ErrParse, "invalid JSON")
			continue
		}
		if !m.isRequest() {
			// Agents don't receive notifications or responses in this protocol.
			s.respondError(m.ID, ErrInvalidRequest, "expected a request")
			continue
		}
		s.dispatch(&m)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	return nil // clean EOF
}

func (s *server) dispatch(m *message) {
	switch m.Method {
	case MethodInitialize:
		var p InitializeParams
		if err := json.Unmarshal(m.Params, &p); err != nil {
			s.respondError(m.ID, ErrInvalidParams, "bad initialize params")
			return
		}
		if p.Version != Version {
			s.respondError(m.ID, ErrUnsupported, fmt.Sprintf("unsupported version %d (want %d)", p.Version, Version))
			return
		}
		pub, err := s.h.Initialize(p.Locator)
		if err != nil {
			s.respondError(m.ID, errCode(err, ErrNoKey), err.Error())
			return
		}
		s.respondResult(m.ID, InitializeResult{
			Version:   Version,
			PublicKey: base64.StdEncoding.EncodeToString(pub[:]),
		})

	case MethodSharedSecret:
		var p SharedSecretParams
		if err := json.Unmarshal(m.Params, &p); err != nil {
			s.respondError(m.ID, ErrInvalidParams, "bad shared_secret params")
			return
		}
		peer, err := decodeKey(p.Peer)
		if err != nil {
			s.respondError(m.ID, ErrInvalidParams, "peer: "+err.Error())
			return
		}
		ss, err := s.h.SharedSecret(peer)
		if err != nil {
			s.respondError(m.ID, errCode(err, ErrHardware), err.Error())
			return
		}
		s.respondResult(m.ID, SharedSecretResult{
			SharedSecret: base64.StdEncoding.EncodeToString(ss[:]),
		})

	default:
		s.respondError(m.ID, ErrMethodNotFound, "unknown method: "+m.Method)
	}
}

func (s *server) respondResult(id *uint64, result any) {
	raw, err := json.Marshal(result)
	if err != nil {
		s.respondError(id, ErrInternal, "marshal result")
		return
	}
	s.write(&message{JSONRPC: "2.0", ID: id, Result: raw})
}

func (s *server) respondError(id *uint64, code int, msg string) {
	s.write(&message{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
}

func (s *server) write(m *message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	_ = s.enc.Encode(m)
}

// errCode lets a Handler choose a wire error code by returning a *CodedError;
// otherwise fallback is used.
func errCode(err error, fallback int) int {
	var ce *CodedError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return fallback
}

// CodedError lets a Handler attach a keyproto error code to an error it returns.
type CodedError struct {
	Code int
	Err  error
}

func (e *CodedError) Error() string { return e.Err.Error() }
func (e *CodedError) Unwrap() error { return e.Err }

// ---------- host side ----------

// Client is the host end of a keyproto connection. It is safe for concurrent
// use by multiple goroutines (WireGuard calls SharedSecret from several
// handshake workers). A single background goroutine reads the connection and
// routes responses to waiting callers and the "removed" notification to Removed.
type Client struct {
	rw io.ReadWriteCloser

	// writeMu serializes encoder writes. It is held ONLY for the duration of an
	// Encode and never together with mu: a socket write can block indefinitely,
	// and the read loop must stay free to drain responses (and so unblock the
	// peer) while a write is in flight. Holding mu across Encode deadlocks —
	// the read loop needs mu to deliver, the write waits for the read loop.
	writeMu sync.Mutex
	enc     *json.Encoder

	// mu guards the pending map, id counter, and closed state. Never held across
	// a socket write.
	mu       sync.Mutex
	nextID   uint64
	pending  map[uint64]chan *message
	closed   bool
	closeErr error

	removed chan struct{} // closed on a removed notification OR on EOF/error
	once    sync.Once
}

// NewClient starts the read loop on rw and returns a ready Client. rw is owned
// by the Client and closed by Close.
func NewClient(rw io.ReadWriteCloser) *Client {
	c := &Client{
		rw:      rw,
		enc:     json.NewEncoder(rw),
		pending: make(map[uint64]chan *message),
		removed: make(chan struct{}),
	}
	go c.readLoop()
	return c
}

// Removed is closed when the agent signals key removal — either via a "removed"
// notification or by the connection closing (EOF/error). The host treats this
// as "the key is gone, tear the tunnel down".
func (c *Client) Removed() <-chan struct{} { return c.removed }

func (c *Client) signalRemoved() { c.once.Do(func() { close(c.removed) }) }

func (c *Client) readLoop() {
	sc := bufio.NewScanner(c.rw)
	sc.Buffer(make([]byte, 0, 4096), maxLineBytes)
	for sc.Scan() {
		var m message
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			continue // ignore unparseable lines
		}
		switch {
		case m.isNotification() && m.Method == MethodRemoved:
			c.signalRemoved()
		case m.isResponse():
			c.deliver(&m)
		}
	}
	// EOF or read error: fail all pending calls and signal removal.
	err := sc.Err()
	if err == nil {
		err = io.EOF
	}
	c.failAll(err)
	c.signalRemoved()
}

func (c *Client) deliver(m *message) {
	c.mu.Lock()
	ch := c.pending[*m.ID]
	delete(c.pending, *m.ID)
	c.mu.Unlock()
	if ch != nil {
		ch <- m
	}
}

func (c *Client) failAll(err error) {
	c.mu.Lock()
	c.closed = true
	c.closeErr = err
	pend := c.pending
	c.pending = map[uint64]chan *message{}
	c.mu.Unlock()
	for _, ch := range pend {
		close(ch) // a nil message tells the caller the conn died
	}
}

// call sends a request and waits for its response.
func (c *Client) call(method string, params any, result any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	ch := make(chan *message, 1)

	// Register the pending call, then release mu BEFORE writing. The write below
	// must not hold mu (see Client.writeMu).
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("keyproto: connection closed: %w", c.closeErr)
	}
	c.nextID++
	id := c.nextID
	c.pending[id] = ch
	c.mu.Unlock()

	c.writeMu.Lock()
	err = c.enc.Encode(&message{JSONRPC: "2.0", ID: &id, Method: method, Params: raw})
	c.writeMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return fmt.Errorf("keyproto: write: %w", err)
	}

	m, ok := <-ch
	if !ok || m == nil {
		return fmt.Errorf("keyproto: connection closed while awaiting %s", method)
	}
	if m.Error != nil {
		return m.Error
	}
	if result != nil {
		if err := json.Unmarshal(m.Result, result); err != nil {
			return fmt.Errorf("keyproto: bad %s result: %w", method, err)
		}
	}
	return nil
}

// Initialize opens the remote identity and returns its 32-byte public key.
func (c *Client) Initialize(locator string) (pub [32]byte, err error) {
	var res InitializeResult
	if err = c.call(MethodInitialize, InitializeParams{Version: Version, Locator: locator}, &res); err != nil {
		return pub, err
	}
	return decodeKey(res.PublicKey)
}

// SharedSecret asks the agent to compute X25519(static_priv, peer).
func (c *Client) SharedSecret(peer [32]byte) (ss [32]byte, err error) {
	var res SharedSecretResult
	p := SharedSecretParams{Peer: base64.StdEncoding.EncodeToString(peer[:])}
	if err = c.call(MethodSharedSecret, p, &res); err != nil {
		return ss, err
	}
	return decodeKey(res.SharedSecret)
}

// Close closes the underlying connection; the read loop then unwinds and
// Removed fires.
func (c *Client) Close() error { return c.rw.Close() }

// decodeKey parses a standard-base64 32-byte key.
func decodeKey(s string) (k [32]byte, err error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("invalid base64: %w", err)
	}
	if len(b) != 32 {
		return k, fmt.Errorf("key is %d bytes, want 32", len(b))
	}
	copy(k[:], b)
	return k, nil
}
