package fuse

import (
	"os"
	"time"

	bazil "bazil.org/fuse"
	bazilfs "bazil.org/fuse/fs"
	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
)

// FS is the root of the Spillway FUSE filesystem.
type FS struct {
	bridge   Bridge
	readOnly bool
}

// NewFS creates a new FS backed by the given bridge.
func NewFS(bridge Bridge, readOnly bool) *FS {
	return &FS{bridge: bridge, readOnly: readOnly}
}

// Root returns the root directory node.
func (f *FS) Root() (bazilfs.Node, error) {
	return &Dir{path: "/", bridge: f.bridge, readOnly: f.readOnly}, nil
}

// knownProtocolErrors is the set of protocol error strings that have a
// defined syscall.Errno mapping.
var knownProtocolErrors = map[string]bool{
	protocol.ErrNotFound:   true,
	protocol.ErrPermission: true,
	protocol.ErrExist:      true,
	protocol.ErrNotDir:     true,
	protocol.ErrIsDir:      true,
	protocol.ErrNotEmpty:   true,
	protocol.ErrIO:         true,
	protocol.ErrInval:      true,
	protocol.ErrNoSys:      true,
	protocol.ErrNoDat:      true,
	protocol.ErrRange:      true,
	protocol.ErrJail:       true,
	protocol.ErrReadOnly:   true,
}

// mapErr converts a protocol error string embedded in err.Error() into a
// bazil.Errno. If no protocol error is recognised the original error is returned.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	if knownProtocolErrors[s] {
		return bazil.Errno(protocol.ToErrno(s))
	}
	return err
}

// fillAttr populates a bazil.Attr from a protocol FileStat.
func fillAttr(st *protocol.FileStat, a *bazil.Attr) {
	a.Valid = time.Second
	a.Size = uint64(st.Size)
	a.Mode = os.FileMode(st.Mode)
	a.Mtime = time.Unix(st.ModTime, 0)
	a.Uid = st.Uid
	a.Gid = st.Gid
	if st.IsDir {
		a.Mode |= os.ModeDir
	}
	if st.IsLink {
		a.Mode |= os.ModeSymlink
	}
}
