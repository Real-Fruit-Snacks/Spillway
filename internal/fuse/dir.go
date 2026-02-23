package fuse

import (
	"context"
	"path"
	"syscall"

	bazil "bazil.org/fuse"
	bazilfs "bazil.org/fuse/fs"
)

// Dir is a FUSE directory node.
type Dir struct {
	path     string
	bridge   Bridge
	readOnly bool
}

// Attr fetches file attributes for this directory.
func (d *Dir) Attr(ctx context.Context, a *bazil.Attr) error {
	st, err := d.bridge.Stat(d.path)
	if err != nil {
		return mapErr(err)
	}
	fillAttr(st, a)
	return nil
}

// Lookup looks up a child entry by name.
func (d *Dir) Lookup(ctx context.Context, name string) (bazilfs.Node, error) {
	childPath := path.Join(d.path, name)
	st, err := d.bridge.Stat(childPath)
	if err != nil {
		return nil, mapErr(err)
	}
	if st.IsDir || (st.IsLink && st.IsDir) {
		return &Dir{path: childPath, bridge: d.bridge, readOnly: d.readOnly}, nil
	}
	return &File{path: childPath, bridge: d.bridge, readOnly: d.readOnly}, nil
}

// ReadDirAll returns all entries in this directory.
func (d *Dir) ReadDirAll(ctx context.Context) ([]bazil.Dirent, error) {
	entries, err := d.bridge.ReadDir(d.path)
	if err != nil {
		return nil, mapErr(err)
	}
	dirents := make([]bazil.Dirent, 0, len(entries))
	for _, e := range entries {
		dt := bazil.DT_File
		if e.IsDir {
			dt = bazil.DT_Dir
		}
		dirents = append(dirents, bazil.Dirent{Name: e.Name, Type: dt})
	}
	return dirents, nil
}

// Mkdir creates a new subdirectory.
func (d *Dir) Mkdir(ctx context.Context, req *bazil.MkdirRequest) (bazilfs.Node, error) {
	if d.readOnly {
		return nil, bazil.Errno(syscall.EROFS)
	}
	childPath := path.Join(d.path, req.Name)
	if err := d.bridge.Mkdir(childPath, uint32(req.Mode)); err != nil {
		return nil, mapErr(err)
	}
	return &Dir{path: childPath, bridge: d.bridge, readOnly: d.readOnly}, nil
}

// Create creates a new file in this directory.
func (d *Dir) Create(ctx context.Context, req *bazil.CreateRequest, resp *bazil.CreateResponse) (bazilfs.Node, bazilfs.Handle, error) {
	if d.readOnly {
		return nil, nil, bazil.Errno(syscall.EROFS)
	}
	childPath := path.Join(d.path, req.Name)
	if err := d.bridge.Create(childPath, uint32(req.Mode)); err != nil {
		return nil, nil, mapErr(err)
	}
	f := &File{path: childPath, bridge: d.bridge, readOnly: d.readOnly}
	return f, f, nil
}

// Remove removes a child file or directory.
func (d *Dir) Remove(ctx context.Context, req *bazil.RemoveRequest) error {
	if d.readOnly {
		return bazil.Errno(syscall.EROFS)
	}
	childPath := path.Join(d.path, req.Name)
	return mapErr(d.bridge.Remove(childPath))
}

// Rename renames a child entry, potentially moving it into newDir.
func (d *Dir) Rename(ctx context.Context, req *bazil.RenameRequest, newDir bazilfs.Node) error {
	if d.readOnly {
		return bazil.Errno(syscall.EROFS)
	}
	nd, ok := newDir.(*Dir)
	if !ok {
		return bazil.Errno(syscall.EINVAL)
	}
	oldPath := path.Join(d.path, req.OldName)
	newPath := path.Join(nd.path, req.NewName)
	return mapErr(d.bridge.Rename(oldPath, newPath))
}
