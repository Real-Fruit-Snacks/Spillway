package transport

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
)

// bufferedConn wraps a net.Conn so that bytes already consumed into a bufio.Reader
// are still available for subsequent reads through the net.Conn interface.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.r.Read(p)
}

// DialViaProxy establishes a TCP tunnel through an HTTP CONNECT proxy.
// proxyUser and proxyPass may be empty if the proxy requires no authentication.
func DialViaProxy(ctx context.Context, proxyAddr, targetAddr, proxyUser, proxyPass string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}

	// Build the CONNECT request.
	req, err := http.NewRequest(http.MethodConnect, "http://"+targetAddr, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("build CONNECT request: %w", err)
	}
	req.Host = targetAddr

	if proxyUser != "" || proxyPass != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(proxyUser + ":" + proxyPass))
		req.Header.Set("Proxy-Authorization", "Basic "+creds)
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}

	// Parse the response. Use a bufio.Reader so we don't over-consume bytes
	// that belong to the tunnelled stream.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	// If the bufio.Reader has already buffered bytes beyond the HTTP response,
	// wrap the connection so those bytes are served first.
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}
