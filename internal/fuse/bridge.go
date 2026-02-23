package fuse

import "github.com/Real-Fruit-Snacks/Spillway/internal/protocol"

// Bridge is the contract between FUSE nodes and the remote session.
type Bridge interface {
	Stat(path string) (*protocol.FileStat, error)
	ReadDir(path string) ([]protocol.DirEntry, error)
	ReadFile(path string, offset int64, size int64) ([]byte, error)
	ReadLink(path string) (string, error)
	WriteFile(path string, data []byte, offset int64) (int64, error)
	Create(path string, mode uint32) error
	Mkdir(path string, mode uint32) error
	Remove(path string) error
	Rename(oldPath, newPath string) error
	Chmod(path string, mode uint32) error
	Truncate(path string, size int64) error
	Chown(path string, uid, gid uint32) error
	Symlink(target, linkName string) error
	Link(oldPath, newPath string) error
	Statfs(path string) (*protocol.StatfsInfo, error)
	Getxattr(path, name string) ([]byte, error)
	Listxattr(path string) ([]string, error)
}
