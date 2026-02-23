//go:build !linux && !darwin && !windows

package agent

import (
	"syscall"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
)

func statfs(_ string) (*protocol.StatfsInfo, error) {
	return nil, syscall.ENOSYS
}
