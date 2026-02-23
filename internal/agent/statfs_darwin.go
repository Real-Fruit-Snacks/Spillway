//go:build darwin

package agent

import (
	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
	"golang.org/x/sys/unix"
)

func statfs(path string) (*protocol.StatfsInfo, error) {
	var buf unix.Statfs_t
	if err := unix.Statfs(path, &buf); err != nil {
		return nil, err
	}
	return &protocol.StatfsInfo{
		TotalBlocks: buf.Blocks,
		FreeBlocks:  buf.Bfree,
		AvailBlocks: buf.Bavail,
		TotalInodes: buf.Files,
		FreeInodes:  buf.Ffree,
		BlockSize:   uint32(buf.Bsize),
		MaxNameLen:  255, // NAME_MAX on macOS
	}, nil
}
