package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
)

// maxPSKLen is the maximum allowed pre-shared key length in bytes.
const maxPSKLen = 256

// AgentTLSConfig returns a TLS 1.3 client config that verifies the server
// certificate by SHA-256 fingerprint rather than by CA chain.
// fingerprint must be a hex-encoded SHA-256 digest (64 hex chars), optionally
// with colon separators (e.g. "aa:bb:cc:...").
func AgentTLSConfig(sni string, fingerprint string) *tls.Config {
	// Normalise fingerprint: strip colons, lower-case.
	normalized := strings.ToLower(strings.NewReplacer(":", "").Replace(fingerprint))

	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // fingerprint checked below when provided
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	// Only set fingerprint verification when a fingerprint is provided.
	// Without a fingerprint, TLS encryption is still active but the server
	// certificate is not pinned (PSK auth provides identity assurance instead).
	if normalized != "" {
		pinned := normalized // capture for closure
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("tls: no peer certificate presented")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("tls: parse peer cert: %w", err)
			}
			got := sha256.Sum256(cert.Raw)
			gotHex := hex.EncodeToString(got[:])
			if gotHex != pinned {
				return fmt.Errorf("tls: certificate fingerprint mismatch: got %s, want %s", gotHex, pinned)
			}
			return nil
		}
	}

	return cfg
}

// ListenerTLSConfig returns a TLS 1.3 server config loaded from PEM-encoded
// certificate and private key.
func ListenerTLSConfig(certPEM, keyPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tls: load key pair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}

// PerformAuth is the client-side mutual PSK handshake.
//
// Round 1 (client challenges server):
//  1. Generate 32-byte random nonce (clientNonce).
//  2. Send MsgAuth with clientNonce in Nonce field.
//  3. Read MsgAuthResp — verify HMAC-SHA256(psk, clientNonce).
//
// Round 2 (server challenges client):
//  4. Read MsgAuth with serverNonce in Nonce field.
//  5. Compute HMAC-SHA256(psk, serverNonce), send MsgAuthResp.
func PerformAuth(conn *FramedConn, psk []byte) error {
	if len(psk) == 0 {
		return errors.New("auth: PSK must not be empty")
	}
	if len(psk) > maxPSKLen {
		return errors.New("auth: PSK exceeds maximum length")
	}
	// Round 1: challenge the server.
	clientNonce := make([]byte, 32)
	if _, err := rand.Read(clientNonce); err != nil {
		return fmt.Errorf("auth: generate nonce: %w", err)
	}

	req := &protocol.Request{
		Type:  protocol.MsgAuth,
		ID:    0,
		Nonce: clientNonce,
	}
	if err := conn.WriteFrame(protocol.MarshalRequest(req)); err != nil {
		return fmt.Errorf("auth: send client challenge: %w", err)
	}

	frame, err := conn.ReadFrame()
	if err != nil {
		return fmt.Errorf("auth: read server response: %w", err)
	}
	resp, err := protocol.UnmarshalResponse(frame)
	if err != nil {
		return fmt.Errorf("auth: unmarshal server response: %w", err)
	}
	if resp.Type != protocol.MsgAuthResp {
		return fmt.Errorf("auth: unexpected response type 0x%02x", resp.Type)
	}
	if resp.Error != "" {
		return fmt.Errorf("auth: server error: %s", resp.Error)
	}

	expected := computeHMAC(psk, clientNonce)
	if !hmac.Equal(resp.Data, expected) {
		return errors.New("auth: server HMAC verification failed")
	}

	// Round 2: respond to server's challenge.
	frame, err = conn.ReadFrame()
	if err != nil {
		return fmt.Errorf("auth: read server challenge: %w", err)
	}
	serverReq, err := protocol.UnmarshalRequest(frame)
	if err != nil {
		return fmt.Errorf("auth: unmarshal server challenge: %w", err)
	}
	if serverReq.Type != protocol.MsgAuth {
		return fmt.Errorf("auth: unexpected challenge type 0x%02x", serverReq.Type)
	}

	mac := computeHMAC(psk, serverReq.Nonce)
	clientResp := &protocol.Response{
		Type: protocol.MsgAuthResp,
		ID:   serverReq.ID,
		Data: mac,
	}
	if err := conn.WriteFrame(protocol.MarshalResponse(clientResp)); err != nil {
		return fmt.Errorf("auth: send client response: %w", err)
	}

	return nil
}

// ValidateAuth is the server-side mutual PSK handshake.
//
// Round 1 (client challenges server):
//  1. Read MsgAuth with clientNonce.
//  2. Compute HMAC-SHA256(psk, clientNonce), send MsgAuthResp.
//
// Round 2 (server challenges client):
//  3. Generate serverNonce, send MsgAuth.
//  4. Read MsgAuthResp — verify HMAC-SHA256(psk, serverNonce).
func ValidateAuth(conn *FramedConn, psk []byte) error {
	if len(psk) == 0 {
		return errors.New("auth: PSK must not be empty")
	}
	if len(psk) > maxPSKLen {
		return errors.New("auth: PSK exceeds maximum length")
	}

	// Round 1: respond to client's challenge.
	frame, err := conn.ReadFrame()
	if err != nil {
		return fmt.Errorf("auth: read client challenge: %w", err)
	}
	req, err := protocol.UnmarshalRequest(frame)
	if err != nil {
		return fmt.Errorf("auth: unmarshal client challenge: %w", err)
	}
	if req.Type != protocol.MsgAuth {
		return fmt.Errorf("auth: unexpected request type 0x%02x", req.Type)
	}

	mac := computeHMAC(psk, req.Nonce)
	resp := &protocol.Response{
		Type: protocol.MsgAuthResp,
		ID:   req.ID,
		Data: mac,
	}
	if err := conn.WriteFrame(protocol.MarshalResponse(resp)); err != nil {
		return fmt.Errorf("auth: send server response: %w", err)
	}

	// Round 2: challenge the client.
	serverNonce := make([]byte, 32)
	if _, err := rand.Read(serverNonce); err != nil {
		return fmt.Errorf("auth: generate server nonce: %w", err)
	}

	challenge := &protocol.Request{
		Type:  protocol.MsgAuth,
		ID:    1,
		Nonce: serverNonce,
	}
	if err := conn.WriteFrame(protocol.MarshalRequest(challenge)); err != nil {
		return fmt.Errorf("auth: send server challenge: %w", err)
	}

	frame, err = conn.ReadFrame()
	if err != nil {
		return fmt.Errorf("auth: read client response: %w", err)
	}
	clientResp, err := protocol.UnmarshalResponse(frame)
	if err != nil {
		return fmt.Errorf("auth: unmarshal client response: %w", err)
	}
	if clientResp.Type != protocol.MsgAuthResp {
		return fmt.Errorf("auth: unexpected response type 0x%02x", clientResp.Type)
	}
	if clientResp.Error != "" {
		return fmt.Errorf("auth: client error: %s", clientResp.Error)
	}

	expected := computeHMAC(psk, serverNonce)
	if !hmac.Equal(clientResp.Data, expected) {
		return errors.New("auth: client HMAC verification failed")
	}

	return nil
}

// computeHMAC returns HMAC-SHA256(key, message).
func computeHMAC(key, message []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}
