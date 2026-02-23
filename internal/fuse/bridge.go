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
}
