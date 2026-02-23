package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
)

// maxInflight is the maximum number of concurrent in-flight requests.
const maxInflight = 64

// errMuxClosed is returned when a call is made on a closed mux.
var errMuxClosed = errors.New("mux: connection closed")

// RateLimiter is implemented by callers that want to throttle ServerMux writes.
type RateLimiter interface {
	// Wait blocks until n bytes may be sent.
	Wait(n int)
}

// -----------------------------------------------------------------------
// ClientMux
// -----------------------------------------------------------------------

// pendingCall holds the response channel for one in-flight request.
type pendingCall struct {
	ch chan *protocol.Response
}

// ClientMux multiplexes protocol calls over a single FramedConn.
// It is used by the listener / FUSE side.
type ClientMux struct {
	conn    *FramedConn
	pending sync.Map // uint32 ID → *pendingCall

	sendCh chan []byte   // writer goroutine input
	sem    chan struct{} // bounds in-flight requests to maxInflight
	nextID atomic.Uint32

	done     chan struct{} // closed when mux is shut down
	once     sync.Once
	closeErr atomic.Value // stores error
}

// NewClientMux creates a ClientMux and starts its internal goroutines.
func NewClientMux(conn *FramedConn) *ClientMux {
	m := &ClientMux{
		conn:   conn,
		sendCh: make(chan []byte, maxInflight),
		sem:    make(chan struct{}, maxInflight),
		done:   make(chan struct{}),
	}
	// Pre-fill semaphore.
	for i := 0; i < maxInflight; i++ {
		m.sem <- struct{}{}
	}
	go m.reader()
	go m.writer()
	return m
}

// Done returns a channel that is closed when the mux shuts down.
func (m *ClientMux) Done() <-chan struct{} {
	return m.done
}

// Call sends req and blocks until the matching response arrives or ctx expires.
func (m *ClientMux) Call(ctx context.Context, req *protocol.Request) (*protocol.Response, error) {
	// Acquire semaphore slot (respects ctx cancellation).
	select {
	case <-m.sem:
	case <-m.done:
		return nil, errMuxClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Assign unique ID.
	id := m.nextID.Add(1)
	req.ID = id

	ch := make(chan *protocol.Response, 1)
	m.pending.Store(id, &pendingCall{ch: ch})

	frame := protocol.MarshalRequest(req)

	// Enqueue frame for writer goroutine.
	select {
	case m.sendCh <- frame:
	case <-m.done:
		m.pending.Delete(id)
		m.sem <- struct{}{}
		return nil, errMuxClosed
	case <-ctx.Done():
		m.pending.Delete(id)
		m.sem <- struct{}{}
		return nil, ctx.Err()
	}

	// Wait for response.
	select {
	case resp := <-ch:
		m.sem <- struct{}{}
		return resp, nil
	case <-m.done:
		m.pending.Delete(id)
		m.sem <- struct{}{}
		return nil, errMuxClosed
	case <-ctx.Done():
		m.pending.Delete(id)
		m.sem <- struct{}{}
		return nil, ctx.Err()
	}
}

// Close shuts the mux down, completing all pending calls with an error.
func (m *ClientMux) Close() {
	m.once.Do(func() {
		m.closeErr.Store(errMuxClosed)
		m.conn.Close()
		close(m.done)
		// Drain pending calls.
		m.pending.Range(func(k, v any) bool {
			if pc, ok := v.(*pendingCall); ok {
				// Non-blocking; Call() will see done channel close.
				select {
				case pc.ch <- &protocol.Response{Error: errMuxClosed.Error()}:
				default:
				}
			}
			m.pending.Delete(k)
			return true
		})
	})
}

func (m *ClientMux) reader() {
	defer m.Close()
	for {
		frame, err := m.conn.ReadFrame()
		if err != nil {
			return
		}
		resp, err := protocol.UnmarshalResponse(frame)
		if err != nil {
			// Malformed frame — skip.
			continue
		}
		if v, ok := m.pending.LoadAndDelete(resp.ID); ok {
			if pc, ok := v.(*pendingCall); ok {
				select {
				case pc.ch <- resp:
				default:
				}
			}
		}
	}
}

func (m *ClientMux) writer() {
	for {
		select {
		case frame := <-m.sendCh:
			if err := m.conn.WriteFrame(frame); err != nil {
				m.Close()
				return
			}
		case <-m.done:
			return
		}
	}
}

// -----------------------------------------------------------------------
// ServerMux
// -----------------------------------------------------------------------

// serverWork is a unit dispatched to a worker goroutine.
type serverWork struct {
	frame []byte
}

// serverResp is the result from a worker, queued for the writer goroutine.
type serverResp struct {
	frame []byte
}

// ServerMux reads requests from a FramedConn, dispatches them to a worker pool,
// and serialises responses back through a writer goroutine.
// It is used by the agent side.
type ServerMux struct {
	conn    *FramedConn
	handler func(*protocol.Request) *protocol.Response

	workCh chan serverWork // reader → workers
	respCh chan serverResp // workers → writer
	done   chan struct{}
	once   sync.Once
	rl     RateLimiter // optional; nil means no rate limit
	rlMu   sync.RWMutex
}

// NewServerMux creates a ServerMux. Call Run() to start processing.
func NewServerMux(conn *FramedConn, handler func(*protocol.Request) *protocol.Response) *ServerMux {
	return &ServerMux{
		conn:    conn,
		handler: handler,
		workCh:  make(chan serverWork, maxInflight),
		respCh:  make(chan serverResp, maxInflight),
		done:    make(chan struct{}),
	}
}

// Done returns a channel that is closed when the mux shuts down.
func (s *ServerMux) Done() <-chan struct{} {
	return s.done
}

// SetRateLimiter installs a rate limiter applied before each write.
// Safe to call before Run().
func (s *ServerMux) SetRateLimiter(rl RateLimiter) {
	s.rlMu.Lock()
	s.rl = rl
	s.rlMu.Unlock()
}

// Run starts the reader, worker pool, and writer goroutines and blocks until
// the connection is closed or Close() is called.
func (s *ServerMux) Run() {
	var wg sync.WaitGroup

	// Start worker pool.
	for i := 0; i < maxInflight; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker()
		}()
	}

	// Writer goroutine.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		s.writer()
	}()

	// Reader (blocks until error or Close).
	s.reader()

	// Signal workers to stop by closing workCh (reader has exited).
	close(s.workCh)
	wg.Wait()

	// Signal writer to stop.
	close(s.respCh)
	<-writerDone
}

// Close shuts the mux down.
func (s *ServerMux) Close() {
	s.once.Do(func() {
		s.conn.Close()
		close(s.done)
	})
}

func (s *ServerMux) reader() {
	defer s.Close()
	for {
		frame, err := s.conn.ReadFrame()
		if err != nil {
			return
		}
		select {
		case s.workCh <- serverWork{frame: frame}:
		case <-s.done:
			return
		}
	}
}

func (s *ServerMux) worker() {
	for work := range s.workCh {
		req, err := protocol.UnmarshalRequest(work.frame)
		if err != nil {
			// Malformed request — send an error response if we can extract an ID.
			// Best-effort: skip on double error.
			continue
		}
		resp := s.handler(req)
		if resp == nil {
			resp = &protocol.Response{
				Type:  req.Type | 0x80,
				ID:    req.ID,
				Error: fmt.Sprintf("handler returned nil for type 0x%02x", req.Type),
			}
		}
		frame := protocol.MarshalResponse(resp)
		select {
		case s.respCh <- serverResp{frame: frame}:
		case <-s.done:
			return
		}
	}
}

func (s *ServerMux) writer() {
	for resp := range s.respCh {
		s.rlMu.RLock()
		rl := s.rl
		s.rlMu.RUnlock()
		if rl != nil {
			rl.Wait(len(resp.frame))
		}
		if err := s.conn.WriteFrame(resp.frame); err != nil {
			s.Close()
			return
		}
	}
}
