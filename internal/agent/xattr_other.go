//go:build !linux && !darwin

package agent

import "syscall"

func getXattr(_, _ string) ([]byte, error) {
	return nil, syscall.ENOSYS
}

func listXattr(_ string) ([]string, error) {
	return nil, syscall.ENOSYS
}
