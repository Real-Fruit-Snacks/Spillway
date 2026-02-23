package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
)

// --- FramedConn tests ---

func TestFramedConn_RoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	fc1 := NewFramedConn(c1)
	fc2 := NewFramedConn(c2)
	defer fc1.Close()
	defer fc2.Close()

	data := []byte("hello framed")
	go func() {
		if err := fc1.WriteFrame(data); err != nil {
			t.Errorf("WriteFrame: %v", err)
		}
	}()

	got, err := fc2.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestFramedConn_LargeFrame(t *testing.T) {
	c1, c2 := net.Pipe()
	fc1 := NewFramedConn(c1)
	fc2 := NewFramedConn(c2)
	defer fc1.Close()
	defer fc2.Close()

	data := bytes.Repeat([]byte("X"), 1<<20) // 1 MiB
	go func() {
		fc1.WriteFrame(data)
	}()

	got, err := fc2.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("large frame mismatch")
	}
}

func TestFramedConn_ConcurrentWrites(t *testing.T) {
	c1, c2 := net.Pipe()
	fc1 := NewFramedConn(c1)
	fc2 := NewFramedConn(c2)
	defer fc1.Close()
	defer fc2.Close()

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			data := []byte{byte(i)}
			fc1.WriteFrame(data)
		}(i)
	}

	received := make(map[byte]bool)
	for i := 0; i < n; i++ {
		frame, err := fc2.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame %d: %v", i, err)
		}
		received[frame[0]] = true
	}
	wg.Wait()

	if len(received) != n {
		t.Errorf("received %d unique frames, want %d", len(received), n)
	}
}

func TestFramedConn_ReadAfterClose(t *testing.T) {
	c1, c2 := net.Pipe()
	fc1 := NewFramedConn(c1)
	fc2 := NewFramedConn(c2)
	fc1.Close()

	_, err := fc2.ReadFrame()
	if err == nil {
		t.Error("expected error reading from closed peer")
	}
}

// --- Auth tests ---

func TestAuth_Success(t *testing.T) {
	c1, c2 := net.Pipe()
	fc1 := NewFramedConn(c1)
	fc2 := NewFramedConn(c2)
	defer fc1.Close()
	defer fc2.Close()

	psk := []byte("test-secret-key-1234567890abcdef")

	errCh := make(chan error, 2)
	go func() { errCh <- PerformAuth(fc1, psk) }()
	go func() { errCh <- ValidateAuth(fc2, psk) }()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("auth error: %v", err)
		}
	}
}

func TestAuth_WrongPSK(t *testing.T) {
	c1, c2 := net.Pipe()
	fc1 := NewFramedConn(c1)
	fc2 := NewFramedConn(c2)

	errCh := make(chan error, 2)
	go func() {
		err := PerformAuth(fc1, []byte("client-key-aaaa"))
		// Close our side so the peer's blocked write/read unblocks.
		fc1.Close()
		errCh <- err
	}()
	go func() {
		err := ValidateAuth(fc2, []byte("server-key-bbbb"))
		fc2.Close()
		errCh <- err
	}()

	var gotErr bool
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			gotErr = true
		}
	}
	if !gotErr {
		t.Error("expected auth failure with mismatched PSK")
	}
}

func TestAuth_EmptyPSK(t *testing.T) {
	// PerformAuth with nil PSK returns immediately without touching the conn.
	// ValidateAuth with empty PSK returns immediately without touching the conn.
	// Use separate pipes so neither side blocks the other.
	c1a, c1b := net.Pipe()
	fc1a := NewFramedConn(c1a)
	defer c1a.Close()
	defer c1b.Close()

	if err := PerformAuth(fc1a, nil); err == nil {
		t.Error("expected error for nil PSK")
	}

	c2a, c2b := net.Pipe()
	fc2a := NewFramedConn(c2a)
	defer c2a.Close()
	defer c2b.Close()

	if err := ValidateAuth(fc2a, []byte{}); err == nil {
		t.Error("expected error for empty PSK")
	}
}

// --- Mux tests ---

func TestMux_RequestResponse(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientFC := NewFramedConn(clientConn)
	serverFC := NewFramedConn(serverConn)

	handler := func(req *protocol.Request) *protocol.Response {
		return &protocol.Response{
			Type: req.Type | 0x80,
			ID:   req.ID,
			Stat: &protocol.FileStat{Name: "test", Size: 42},
		}
	}

	smux := NewServerMux(serverFC, handler)
	go smux.Run()

	cmux := NewClientMux(clientFC)
	defer cmux.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := cmux.Call(ctx, &protocol.Request{Type: protocol.MsgStat, Path: "/test"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.Stat == nil || resp.Stat.Name != "test" || resp.Stat.Size != 42 {
		t.Errorf("unexpected response: %+v", resp)
	}

	smux.Close()
}

func TestMux_ConcurrentCalls(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientFC := NewFramedConn(clientConn)
	serverFC := NewFramedConn(serverConn)

	handler := func(req *protocol.Request) *protocol.Response {
		return &protocol.Response{
			Type:    req.Type | 0x80,
			ID:      req.ID,
			Written: int64(len(req.Path)),
		}
	}

	smux := NewServerMux(serverFC, handler)
	go smux.Run()

	cmux := NewClientMux(clientFC)
	defer cmux.Close()

	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			path := string(rune('A' + i%26))
			resp, err := cmux.Call(ctx, &protocol.Request{
				Type: protocol.MsgWriteFile,
				Path: path,
			})
			if err != nil {
				errs <- err
				return
			}
			if resp.Written != int64(len(path)) {
				errs <- io.ErrUnexpectedEOF
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent call error: %v", err)
	}

	smux.Close()
}

func TestMux_ContextTimeout(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientFC := NewFramedConn(clientConn)
	serverFC := NewFramedConn(serverConn)

	// Handler that blocks until the server mux shuts down.
	var smux *ServerMux
	handler := func(req *protocol.Request) *protocol.Response {
		select {
		case <-smux.Done():
		case <-time.After(time.Hour):
		}
		return &protocol.Response{Type: req.Type | 0x80, ID: req.ID}
	}

	smux = NewServerMux(serverFC, handler)
	go smux.Run()

	cmux := NewClientMux(clientFC)
	defer cmux.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := cmux.Call(ctx, &protocol.Request{Type: protocol.MsgStat, Path: "/slow"})
	if err == nil {
		t.Error("expected timeout error")
	}

	smux.Close()
}

func TestMux_CloseWhileCallInFlight(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientFC := NewFramedConn(clientConn)
	serverFC := NewFramedConn(serverConn)

	// Handler that blocks until the server mux shuts down.
	var smux *ServerMux
	handler := func(req *protocol.Request) *protocol.Response {
		select {
		case <-smux.Done():
		case <-time.After(time.Hour):
		}
		return &protocol.Response{Type: req.Type | 0x80, ID: req.ID}
	}

	smux = NewServerMux(serverFC, handler)
	go smux.Run()

	cmux := NewClientMux(clientFC)

	go func() {
		time.Sleep(50 * time.Millisecond)
		cmux.Close()
	}()

	ctx := context.Background()
	_, err := cmux.Call(ctx, &protocol.Request{Type: protocol.MsgStat, Path: "/test"})
	if err == nil {
		t.Error("expected error when mux closed during call")
	}

	smux.Close()
}

func TestMux_CallAfterClose(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientFC := NewFramedConn(clientConn)
	_ = NewFramedConn(serverConn)

	cmux := NewClientMux(clientFC)
	cmux.Close()

	ctx := context.Background()
	_, err := cmux.Call(ctx, &protocol.Request{Type: protocol.MsgStat, Path: "/test"})
	if err == nil {
		t.Error("expected error calling closed mux")
	}
	serverConn.Close()
}
