package listener

import (
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/Real-Fruit-Snacks/Spillway/internal/cache"
	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
	"github.com/Real-Fruit-Snacks/Spillway/internal/transport"
)

const callTimeout = 30 * time.Second

// protoError carries a raw protocol error code string so that the FUSE
// layer's mapErr can match it against syscall.Errno via protocol.ToErrno.
type protoError struct {
	code string
}

func (e *protoError) Error() string { return e.code }

// Session implements fuse.Bridge. It owns a ClientMux and Cache.
type Session struct {
	id        string
	mux       *transport.ClientMux
	cache     *cache.Cache
	readOnly  bool
	connected atomic.Bool
}

// NewSession creates a Session that is immediately marked connected.
func NewSession(id string, mux *transport.ClientMux, readOnly bool, cacheTTL time.Duration) *Session {
	s := &Session{
		id:       id,
		mux:      mux,
		cache:    cache.New(cacheTTL, cacheTTL),
		readOnly: readOnly,
	}
	s.connected.Store(true)
	return s
}

// StartEviction starts the cache's background eviction goroutine.
func (s *Session) StartEviction(ctx context.Context) {
	s.cache.StartEviction(ctx)
}

// startKeepalive sends periodic MsgPing requests to the agent. If 3
// consecutive pings fail the mux is closed, tearing down the session.
func (s *Session) startKeepalive(ctx context.Context) {
	go func() {
		missed := 0
		for {
			// 30s ± 30% jitter
			delta := float64(30*time.Second) * 0.3
			offset := (rand.Float64()*2 - 1) * delta //nolint:gosec
			sleep := 30*time.Second + time.Duration(offset)

			select {
			case <-ctx.Done():
				return
			case <-time.After(sleep):
			}

			pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, err := s.mux.Call(pingCtx, &protocol.Request{Type: protocol.MsgPing})
			cancel()
			if err != nil {
				missed++
				if missed >= 3 {
					s.mux.Close()
					return
				}
			} else {
				missed = 0
			}
		}
	}()
}

// Close marks the session disconnected and closes the underlying mux.
func (s *Session) Close() {
	s.connected.Store(false)
	s.mux.Close()
}

// call issues a single RPC with a 30-second timeout.
func (s *Session) call(req *protocol.Request) (*protocol.Response, error) {
	if !s.connected.Load() {
		return nil, &protoError{protocol.ErrIO}
	}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	resp, err := s.mux.Call(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("mux call: %w", err)
	}
	if resp.Error != "" {
		return nil, &protoError{resp.Error}
	}
	return resp, nil
}

// parentDir returns the directory that contains path.
func parentDir(path string) string {
	return filepath.Dir(path)
}

// --- fuse.Bridge implementation ---

func (s *Session) Stat(path string) (*protocol.FileStat, error) {
	if st, ok := s.cache.GetStat(path); ok {
		return st, nil
	}
	resp, err := s.call(&protocol.Request{Type: protocol.MsgStat, Path: path})
	if err != nil {
		return nil, err
	}
	s.cache.PutStat(path, resp.Stat)
	return resp.Stat, nil
}

func (s *Session) ReadDir(path string) ([]protocol.DirEntry, error) {
	if entries, ok := s.cache.GetDir(path); ok {
		return entries, nil
	}
	resp, err := s.call(&protocol.Request{Type: protocol.MsgReadDir, Path: path})
	if err != nil {
		return nil, err
	}
	s.cache.PutDir(path, resp.Entries)
	return resp.Entries, nil
}

func (s *Session) ReadFile(path string, offset int64, size int64) ([]byte, error) {
	resp, err := s.call(&protocol.Request{
		Type:   protocol.MsgReadFile,
		Path:   path,
		Offset: offset,
		Size:   size,
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (s *Session) ReadLink(path string) (string, error) {
	resp, err := s.call(&protocol.Request{Type: protocol.MsgReadLink, Path: path})
	if err != nil {
		return "", err
	}
	if resp.Stat == nil {
		return "", &protoError{protocol.ErrIO}
	}
	return resp.Stat.LinkTarget, nil
}

func (s *Session) WriteFile(path string, data []byte, offset int64) (int64, error) {
	resp, err := s.call(&protocol.Request{
		Type:   protocol.MsgWriteFile,
		Path:   path,
		Data:   data,
		Offset: offset,
	})
	if err != nil {
		return 0, err
	}
	s.cache.InvalidatePath(path)
	s.cache.InvalidatePath(parentDir(path))
	return resp.Written, nil
}

func (s *Session) Create(path string, mode uint32) error {
	_, err := s.call(&protocol.Request{
		Type: protocol.MsgCreate,
		Path: path,
		Mode: mode,
	})
	if err != nil {
		return err
	}
	s.cache.InvalidatePath(path)
	s.cache.InvalidatePath(parentDir(path))
	return nil
}

func (s *Session) Mkdir(path string, mode uint32) error {
	_, err := s.call(&protocol.Request{
		Type: protocol.MsgMkdir,
		Path: path,
		Mode: mode,
	})
	if err != nil {
		return err
	}
	s.cache.InvalidatePath(path)
	s.cache.InvalidatePath(parentDir(path))
	return nil
}

func (s *Session) Remove(path string) error {
	_, err := s.call(&protocol.Request{Type: protocol.MsgRemove, Path: path})
	if err != nil {
		return err
	}
	s.cache.InvalidatePath(path)
	s.cache.InvalidatePath(parentDir(path))
	return nil
}

func (s *Session) Rename(oldPath, newPath string) error {
	_, err := s.call(&protocol.Request{
		Type:  protocol.MsgRename,
		Path:  oldPath,
		Path2: newPath,
	})
	if err != nil {
		return err
	}
	s.cache.InvalidatePath(oldPath)
	s.cache.InvalidatePath(parentDir(oldPath))
	s.cache.InvalidatePath(newPath)
	s.cache.InvalidatePath(parentDir(newPath))
	return nil
}
