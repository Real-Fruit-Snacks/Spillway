package fuse

import (
	"context"
	"syscall"

	bazil "bazil.org/fuse"
)

// File is a FUSE file node.
type File struct {
	path     string
	bridge   Bridge
	readOnly bool
}

// Attr fetches file attributes for this file.
func (f *File) Attr(ctx context.Context, a *bazil.Attr) error {
	st, err := f.bridge.Stat(f.path)
	if err != nil {
		return mapErr(err)
	}
	fillAttr(st, a)
	return nil
}

// Read performs a partial read at the requested offset and size.
func (f *File) Read(ctx context.Context, req *bazil.ReadRequest, resp *bazil.ReadResponse) error {
	data, err := f.bridge.ReadFile(f.path, req.Offset, int64(req.Size))
	if err != nil {
		return mapErr(err)
	}
	resp.Data = data
	return nil
}

// Readlink returns the symlink target for this node.
func (f *File) Readlink(ctx context.Context, req *bazil.ReadlinkRequest) (string, error) {
	target, err := f.bridge.ReadLink(f.path)
	if err != nil {
		return "", mapErr(err)
	}
	return target, nil
}

// Write writes data at the requested offset. Returns EROFS if read-only.
func (f *File) Write(ctx context.Context, req *bazil.WriteRequest, resp *bazil.WriteResponse) error {
	if f.readOnly {
		return bazil.Errno(syscall.EROFS)
	}
	written, err := f.bridge.WriteFile(f.path, req.Data, req.Offset)
	if err != nil {
		return mapErr(err)
	}
	resp.Size = int(written)
	return nil
}
