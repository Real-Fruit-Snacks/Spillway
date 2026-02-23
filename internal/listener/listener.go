package listener

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Real-Fruit-Snacks/Spillway/internal/config"
	"github.com/Real-Fruit-Snacks/Spillway/internal/fuse"
	"github.com/Real-Fruit-Snacks/Spillway/internal/transport"
)

const defaultCacheTTL = 5 * time.Second

// sessionEntry bundles a Session with its mount point for cleanup.
type sessionEntry struct {
	session    *Session
	mountpoint string
}

// Listener manages TLS connections and FUSE mounts.
type Listener struct {
	cfg      *config.ListenerConfig
	sessions sync.Map // string → *sessionEntry

	mu       sync.Mutex
	listener net.Listener // non-nil in reverse mode
}

// New creates a Listener with the given configuration.
func New(cfg *config.ListenerConfig) *Listener {
	return &Listener{cfg: cfg}
}

// Run starts the listener in the configured mode and blocks until ctx is
// cancelled or a fatal error occurs.
func (l *Listener) Run(ctx context.Context) error {
	switch l.cfg.Mode {
	case "bind":
		return l.runBind(ctx)
	default: // "reverse"
		return l.runReverse(ctx)
	}
}

// runReverse listens for incoming agent connections.
func (l *Listener) runReverse(ctx context.Context) error {
	certPEM := l.cfg.CertPEM
	keyPEM := l.cfg.KeyPEM

	if len(certPEM) == 0 || len(keyPEM) == 0 {
		var err error
		certPEM, keyPEM, err = l.generateSelfSignedCert()
		if err != nil {
			return fmt.Errorf("generate cert: %w", err)
		}
	}

	tlsCfg, err := transport.ListenerTLSConfig(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}

	addr := l.cfg.ListenAddr
	if addr == "" {
		addr = ":4444"
	}

	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	l.mu.Lock()
	l.listener = ln
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		ln.Close()
		l.listener = nil
		l.mu.Unlock()
	}()

	// Close listener when ctx is cancelled.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go func(c net.Conn) {
			if err := l.handleConn(ctx, c); err != nil {
				// Connection-level errors (auth failure, disconnect) are
				// expected during normal operation — log to stderr.
				fmt.Fprintf(os.Stderr, "session %s: %v\n", c.RemoteAddr(), err)
			}
		}(conn)
	}
}

// runBind dials the agent and handles the connection.
func (l *Listener) runBind(ctx context.Context) error {
	addr := l.cfg.ConnectAddr
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	return l.handleConn(ctx, rawConn)
}

// handleConn authenticates, creates a Session, mounts FUSE, and blocks until
// the mount exits.
func (l *Listener) handleConn(ctx context.Context, conn net.Conn) error {
	fc := transport.NewFramedConn(conn)

	// Auth: in reverse mode the agent connects to us, so we validate.
	// In bind mode we connect to the agent, so we perform auth.
	var authErr error
	if l.cfg.Mode == "bind" {
		authErr = transport.PerformAuth(fc, l.cfg.PSK)
	} else {
		authErr = transport.ValidateAuth(fc, l.cfg.PSK)
	}
	if authErr != nil {
		fc.Close()
		return fmt.Errorf("auth: %w", authErr)
	}

	mux := transport.NewClientMux(fc)

	// Generate session ID from remote addr + timestamp.
	sessionID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano())
	// Sanitize for use as a path component.
	sessionID = sanitizeID(sessionID)

	cacheTTL := defaultCacheTTL
	if l.cfg.CacheTTL > 0 {
		cacheTTL = time.Duration(l.cfg.CacheTTL) * time.Second
	}

	session := NewSession(sessionID, mux, l.cfg.ReadOnly, cacheTTL)
	session.StartEviction(ctx)
	session.startKeepalive(ctx)

	mountpoint := l.cfg.MountPoint
	if mountpoint == "" {
		mountpoint = fmt.Sprintf("/tmp/spillway-%s", sessionID)
	}

	entry := &sessionEntry{session: session, mountpoint: mountpoint}
	l.sessions.Store(sessionID, entry)
	defer l.sessions.Delete(sessionID)

	// Ensure mux is closed when context is cancelled.
	go func() {
		select {
		case <-ctx.Done():
			session.Close()
		case <-mux.Done():
		}
	}()

	if err := fuse.Mount(mountpoint, session, l.cfg.ReadOnly); err != nil {
		session.Close()
		return fmt.Errorf("mount: %w", err)
	}

	session.Close()
	return nil
}

// Stop unmounts all active sessions and closes all connections.
func (l *Listener) Stop() {
	// Close the listener to stop accepting new connections.
	l.mu.Lock()
	if l.listener != nil {
		l.listener.Close()
	}
	l.mu.Unlock()

	// Unmount and close all sessions.
	l.sessions.Range(func(k, v any) bool {
		if e, ok := v.(*sessionEntry); ok {
			_ = fuse.Unmount(e.mountpoint)
			e.session.Close()
		}
		return true
	})
}

// generateSelfSignedCert generates an ECDSA P-256 self-signed TLS certificate.
func (l *Listener) generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// sanitizeID replaces characters that are not safe for path components.
func sanitizeID(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}
