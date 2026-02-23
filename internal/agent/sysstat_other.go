//go:build !linux

package agent

import (
	"os"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
)

func fillSysStat(st *protocol.FileStat, info os.FileInfo) {
	// Uid/Gid not available on this platform; leave as zero.
}
