// Package transport provides connection abstractions for the Spillway wire protocol.
package transport

import (
	"net"
	"sync"
	"time"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
)

// FramedConn wraps a net.Conn with length-prefixed frame read/write.
type FramedConn struct {
	conn net.Conn
	mu   sync.Mutex // protects WriteFrame
}

// NewFramedConn wraps conn with framing support.
func NewFramedConn(conn net.Conn) *FramedConn {
	return &FramedConn{conn: conn}
}

// ReadFrame reads one length-prefixed frame from the connection.
// ReadFrame is NOT safe for concurrent callers — only one goroutine should
// read at a time (typically the mux reader goroutine).
func (fc *FramedConn) ReadFrame() ([]byte, error) {
	return protocol.ReadFrame(fc.conn)
}

// WriteFrame writes one length-prefixed frame to the connection.
// It is safe for concurrent callers.
func (fc *FramedConn) WriteFrame(data []byte) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return protocol.WriteFrame(fc.conn, data)
}

// Close closes the underlying connection.
func (fc *FramedConn) Close() error {
	return fc.conn.Close()
}

// SetDeadline sets read and write deadlines on the underlying connection.
func (fc *FramedConn) SetDeadline(t time.Time) error {
	return fc.conn.SetDeadline(t)
}

// RemoteAddr returns the remote network address.
func (fc *FramedConn) RemoteAddr() net.Addr {
	return fc.conn.RemoteAddr()
}
