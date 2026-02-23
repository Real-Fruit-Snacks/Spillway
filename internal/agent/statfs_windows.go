//go:build windows

package agent

import (
	"unsafe"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
	"golang.org/x/sys/windows"
)

func statfs(path string) (*protocol.StatfsInfo, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(pathPtr, (*uint64)(unsafe.Pointer(&freeBytesAvailable)), (*uint64)(unsafe.Pointer(&totalBytes)), (*uint64)(unsafe.Pointer(&totalFreeBytes))); err != nil {
		return nil, err
	}
	const blockSize = 4096
	return &protocol.StatfsInfo{
		TotalBlocks: totalBytes / blockSize,
		FreeBlocks:  totalFreeBytes / blockSize,
		AvailBlocks: freeBytesAvailable / blockSize,
		BlockSize:   blockSize,
		MaxNameLen:  255,
	}, nil
}
