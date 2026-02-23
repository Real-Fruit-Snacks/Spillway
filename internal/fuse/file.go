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

// Setattr handles chmod, truncate, chown on files.
func (f *File) Setattr(ctx context.Context, req *bazil.SetattrRequest, resp *bazil.SetattrResponse) error {
	if f.readOnly {
		return bazil.Errno(syscall.EROFS)
	}
	if req.Valid.Mode() {
		if err := f.bridge.Chmod(f.path, uint32(req.Mode)); err != nil {
			return mapErr(err)
		}
	}
	if req.Valid.Size() {
		if err := f.bridge.Truncate(f.path, int64(req.Size)); err != nil {
			return mapErr(err)
		}
	}
	if req.Valid.Uid() || req.Valid.Gid() {
		uid := ^uint32(0) // -1 = don't change
		gid := ^uint32(0)
		if req.Valid.Uid() {
			uid = req.Uid
		}
		if req.Valid.Gid() {
			gid = req.Gid
		}
		if err := f.bridge.Chown(f.path, uid, gid); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

// Getxattr retrieves an extended attribute value.
func (f *File) Getxattr(ctx context.Context, req *bazil.GetxattrRequest, resp *bazil.GetxattrResponse) error {
	data, err := f.bridge.Getxattr(f.path, req.Name)
	if err != nil {
		return mapErr(err)
	}
	resp.Xattr = data
	return nil
}

// Listxattr lists extended attribute names.
func (f *File) Listxattr(ctx context.Context, req *bazil.ListxattrRequest, resp *bazil.ListxattrResponse) error {
	names, err := f.bridge.Listxattr(f.path)
	if err != nil {
		return mapErr(err)
	}
	for _, name := range names {
		resp.Append(name)
	}
	return nil
}
