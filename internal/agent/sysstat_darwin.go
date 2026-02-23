//go:build darwin

package agent

import (
	"os"
	"syscall"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
)

func fillSysStat(st *protocol.FileStat, info os.FileInfo) {
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		st.Uid = sys.Uid
		st.Gid = sys.Gid
	}
}
