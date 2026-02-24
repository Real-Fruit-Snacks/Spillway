package agent

import (
	"io"
	"io/fs"
	"os"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
)

// fileInfoToStat converts an os.FileInfo into a protocol.FileStat.
func fileInfoToStat(path string, info os.FileInfo) *protocol.FileStat {
	st := &protocol.FileStat{
		Name:    info.Name(),
		Size:    info.Size(),
		Mode:    uint32(info.Mode()),
		ModTime: info.ModTime().Unix(),
		IsDir:   info.IsDir(),
		IsLink:  info.Mode()&fs.ModeSymlink != 0,
	}
	fillSysStat(st, info)
	return st
}

// errResp builds a Response carrying only a protocol error string.
func errResp(typ byte, id uint32, protoErr string) *protocol.Response {
	return &protocol.Response{Type: typ, ID: id, Error: protoErr}
}

// resolvePath resolves and checks a path against the jail.
// Returns (resolved, protoErrString). On success protoErrString == "".
func resolvePath(jail *PathJail, raw string, respType byte, id uint32) (string, *protocol.Response) {
	resolved, err := jail.Resolve(raw)
	if err != nil {
		return "", errResp(respType, id, protocol.ErrJail)
	}
	if jail.IsExcluded(resolved) {
		return "", errResp(respType, id, protocol.ErrPermission)
	}
	return resolved, nil
}

func handleStat(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgStatResp, req.ID)
	if errR != nil {
		return errR
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return errResp(protocol.MsgStatResp, req.ID, protocol.FromOSError(err))
	}
	st := fileInfoToStat(resolved, info)
	if info.Mode()&fs.ModeSymlink != 0 {
		target, lerr := os.Readlink(resolved)
		if lerr == nil {
			st.LinkTarget = jail.jailRelative(target)
		}
	}
	return &protocol.Response{Type: protocol.MsgStatResp, ID: req.ID, Stat: st}
}

func handleReadDir(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgReadDirResp, req.ID)
	if errR != nil {
		return errR
	}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return errResp(protocol.MsgReadDirResp, req.ID, protocol.FromOSError(err))
	}
	const maxDirEntries = 100000
	if len(entries) > maxDirEntries {
		entries = entries[:maxDirEntries]
	}
	dirEntries := make([]protocol.DirEntry, 0, len(entries))
	for _, e := range entries {
		info, err2 := e.Info()
		var mode uint32
		if err2 == nil {
			mode = uint32(info.Mode())
		}
		dirEntries = append(dirEntries, protocol.DirEntry{
			Name:  e.Name(),
			IsDir: e.IsDir(),
			Mode:  mode,
		})
	}
	return &protocol.Response{Type: protocol.MsgReadDirResp, ID: req.ID, Entries: dirEntries}
}

func handleReadFile(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgReadFileResp, req.ID)
	if errR != nil {
		return errR
	}
	f, err := os.Open(resolved)
	if err != nil {
		return errResp(protocol.MsgReadFileResp, req.ID, protocol.FromOSError(err))
	}
	defer f.Close()

	if req.Offset > 0 {
		if _, err = f.Seek(req.Offset, io.SeekStart); err != nil {
			return errResp(protocol.MsgReadFileResp, req.ID, protocol.FromOSError(err))
		}
	}

	var data []byte
	readSize := req.Size
	if readSize <= 0 || readSize > protocol.MaxFrameSize {
		readSize = protocol.MaxFrameSize
	}
	data = make([]byte, readSize)
	n, err2 := io.ReadFull(f, data)
	data = data[:n]
	if err2 != nil && err2 != io.ErrUnexpectedEOF && err2 != io.EOF {
		return errResp(protocol.MsgReadFileResp, req.ID, protocol.FromOSError(err2))
	}

	return &protocol.Response{Type: protocol.MsgReadFileResp, ID: req.ID, Data: data}
}

func handleReadLink(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgReadLinkResp, req.ID)
	if errR != nil {
		return errR
	}
	target, err := os.Readlink(resolved)
	if err != nil {
		return errResp(protocol.MsgReadLinkResp, req.ID, protocol.FromOSError(err))
	}
	return &protocol.Response{
		Type: protocol.MsgReadLinkResp,
		ID:   req.ID,
		Stat: &protocol.FileStat{LinkTarget: jail.jailRelative(target)},
	}
}

// handleWriteFile performs a partial write at the requested offset. It does not
// truncate the file — full replacement is achieved by the FUSE layer issuing
// Setattr (truncate) before Write. This is intentional, not a bug.
func handleWriteFile(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgWriteFileResp, req.ID)
	if errR != nil {
		return errR
	}
	f, err := os.OpenFile(resolved, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return errResp(protocol.MsgWriteFileResp, req.ID, protocol.FromOSError(err))
	}
	defer f.Close()

	if req.Offset > 0 {
		if _, err = f.Seek(req.Offset, io.SeekStart); err != nil {
			return errResp(protocol.MsgWriteFileResp, req.ID, protocol.FromOSError(err))
		}
	}

	n, err := f.Write(req.Data)
	if err != nil {
		return errResp(protocol.MsgWriteFileResp, req.ID, protocol.FromOSError(err))
	}
	return &protocol.Response{Type: protocol.MsgWriteFileResp, ID: req.ID, Written: int64(n)}
}

func handleMkdir(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgMkdirResp, req.ID)
	if errR != nil {
		return errR
	}
	mode := fs.FileMode(req.Mode)
	if mode == 0 {
		mode = 0o755
	}
	if err := os.Mkdir(resolved, mode); err != nil {
		return errResp(protocol.MsgMkdirResp, req.ID, protocol.FromOSError(err))
	}
	return &protocol.Response{Type: protocol.MsgMkdirResp, ID: req.ID}
}

func handleRemove(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgRemoveResp, req.ID)
	if errR != nil {
		return errR
	}
	if err := os.Remove(resolved); err != nil {
		return errResp(protocol.MsgRemoveResp, req.ID, protocol.FromOSError(err))
	}
	return &protocol.Response{Type: protocol.MsgRemoveResp, ID: req.ID}
}

func handleRename(req *protocol.Request, jail *PathJail) *protocol.Response {
	src, errR := resolvePath(jail, req.Path, protocol.MsgRenameResp, req.ID)
	if errR != nil {
		return errR
	}
	dst, errR2 := resolvePath(jail, req.Path2, protocol.MsgRenameResp, req.ID)
	if errR2 != nil {
		return errR2
	}
	if err := os.Rename(src, dst); err != nil {
		return errResp(protocol.MsgRenameResp, req.ID, protocol.FromOSError(err))
	}
	return &protocol.Response{Type: protocol.MsgRenameResp, ID: req.ID}
}

func handleChmod(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgChmodResp, req.ID)
	if errR != nil {
		return errR
	}
	if err := os.Chmod(resolved, fs.FileMode(req.Mode)); err != nil {
		return errResp(protocol.MsgChmodResp, req.ID, protocol.FromOSError(err))
	}
	return &protocol.Response{Type: protocol.MsgChmodResp, ID: req.ID}
}

func handleCreate(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgCreateResp, req.ID)
	if errR != nil {
		return errR
	}
	mode := fs.FileMode(req.Mode)
	if mode == 0 {
		mode = 0o644
	}
	f, err := os.OpenFile(resolved, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return errResp(protocol.MsgCreateResp, req.ID, protocol.FromOSError(err))
	}
	f.Close()
	return &protocol.Response{Type: protocol.MsgCreateResp, ID: req.ID}
}

func handleTruncate(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgTruncateResp, req.ID)
	if errR != nil {
		return errR
	}
	if err := os.Truncate(resolved, req.Size); err != nil {
		return errResp(protocol.MsgTruncateResp, req.ID, protocol.FromOSError(err))
	}
	return &protocol.Response{Type: protocol.MsgTruncateResp, ID: req.ID}
}

func handleGetXattr(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgGetXattrResp, req.ID)
	if errR != nil {
		return errR
	}
	data, err := getXattr(resolved, req.XattrName)
	if err != nil {
		return errResp(protocol.MsgGetXattrResp, req.ID, protocol.FromOSError(err))
	}
	return &protocol.Response{Type: protocol.MsgGetXattrResp, ID: req.ID, Data: data}
}

func handleListXattr(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgListXattrResp, req.ID)
	if errR != nil {
		return errR
	}
	names, err := listXattr(resolved)
	if err != nil {
		return errResp(protocol.MsgListXattrResp, req.ID, protocol.FromOSError(err))
	}
	return &protocol.Response{Type: protocol.MsgListXattrResp, ID: req.ID, Names: names}
}

func handleChown(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgChownResp, req.ID)
	if errR != nil {
		return errR
	}
	if err := os.Lchown(resolved, int(req.Uid), int(req.Gid)); err != nil {
		return errResp(protocol.MsgChownResp, req.ID, protocol.FromOSError(err))
	}
	return &protocol.Response{Type: protocol.MsgChownResp, ID: req.ID}
}

func handleSymlink(req *protocol.Request, jail *PathJail) *protocol.Response {
	// Path2 is the link name (must be inside jail). Path is the symlink target
	// and is intentionally NOT jail-checked: the operator controls the listener
	// and may legitimately create symlinks pointing outside the jail root.
	// The jail still prevents reading through such links (EvalSymlinks in Resolve).
	resolved, errR := resolvePath(jail, req.Path2, protocol.MsgSymlinkResp, req.ID)
	if errR != nil {
		return errR
	}
	if err := os.Symlink(req.Path, resolved); err != nil {
		return errResp(protocol.MsgSymlinkResp, req.ID, protocol.FromOSError(err))
	}
	return &protocol.Response{Type: protocol.MsgSymlinkResp, ID: req.ID}
}

func handleLink(req *protocol.Request, jail *PathJail) *protocol.Response {
	src, errR := resolvePath(jail, req.Path, protocol.MsgLinkResp, req.ID)
	if errR != nil {
		return errR
	}
	dst, errR2 := resolvePath(jail, req.Path2, protocol.MsgLinkResp, req.ID)
	if errR2 != nil {
		return errR2
	}
	if err := os.Link(src, dst); err != nil {
		return errResp(protocol.MsgLinkResp, req.ID, protocol.FromOSError(err))
	}
	return &protocol.Response{Type: protocol.MsgLinkResp, ID: req.ID}
}

func handleStatfs(req *protocol.Request, jail *PathJail) *protocol.Response {
	resolved, errR := resolvePath(jail, req.Path, protocol.MsgStatfsResp, req.ID)
	if errR != nil {
		return errR
	}
	info, err := statfs(resolved)
	if err != nil {
		return errResp(protocol.MsgStatfsResp, req.ID, protocol.FromOSError(err))
	}
	return &protocol.Response{Type: protocol.MsgStatfsResp, ID: req.ID, Statfs: info}
}

// isWriteOp returns true for message types that modify the filesystem.
func isWriteOp(typ byte) bool {
	switch typ {
	case protocol.MsgWriteFile, protocol.MsgMkdir, protocol.MsgRemove,
		protocol.MsgRename, protocol.MsgChmod, protocol.MsgCreate,
		protocol.MsgTruncate, protocol.MsgChown, protocol.MsgSymlink,
		protocol.MsgLink:
		return true
	}
	return false
}

// dispatchRequest routes a request to the appropriate handler.
// If readOnly is true, write operations are rejected with EROFS.
func dispatchRequest(req *protocol.Request, jail *PathJail, readOnly bool) *protocol.Response {
	if readOnly && isWriteOp(req.Type) {
		respType := req.Type | 0x80 // Convert request type to response type.
		return errResp(respType, req.ID, protocol.ErrReadOnly)
	}

	switch req.Type {
	case protocol.MsgStat:
		return handleStat(req, jail)
	case protocol.MsgReadDir:
		return handleReadDir(req, jail)
	case protocol.MsgReadFile:
		return handleReadFile(req, jail)
	case protocol.MsgReadLink:
		return handleReadLink(req, jail)
	case protocol.MsgWriteFile:
		return handleWriteFile(req, jail)
	case protocol.MsgMkdir:
		return handleMkdir(req, jail)
	case protocol.MsgRemove:
		return handleRemove(req, jail)
	case protocol.MsgRename:
		return handleRename(req, jail)
	case protocol.MsgChmod:
		return handleChmod(req, jail)
	case protocol.MsgCreate:
		return handleCreate(req, jail)
	case protocol.MsgTruncate:
		return handleTruncate(req, jail)
	case protocol.MsgGetXattr:
		return handleGetXattr(req, jail)
	case protocol.MsgListXattr:
		return handleListXattr(req, jail)
	case protocol.MsgChown:
		return handleChown(req, jail)
	case protocol.MsgSymlink:
		return handleSymlink(req, jail)
	case protocol.MsgLink:
		return handleLink(req, jail)
	case protocol.MsgStatfs:
		return handleStatfs(req, jail)
	default:
		return errResp(protocol.MsgError, req.ID, protocol.ErrInval)
	}
}
