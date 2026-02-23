package fuse

import (
	"os"
	"os/signal"
	"syscall"

	bazil "bazil.org/fuse"
	bazilfs "bazil.org/fuse/fs"
)

// Mount mounts the Spillway filesystem at mountpoint, serves it, and blocks
// until a SIGINT or SIGTERM is received or serving completes.
func Mount(mountpoint string, bridge Bridge, readOnly bool) error {
	if err := os.MkdirAll(mountpoint, 0755); err != nil {
		return err
	}

	opts := []bazil.MountOption{
		bazil.FSName("spillway"),
		bazil.Subtype("spillway"),
		bazil.AsyncRead(),
	}
	if readOnly {
		opts = append(opts, bazil.ReadOnly())
	}

	c, err := bazil.Mount(mountpoint, opts...)
	if err != nil {
		return err
	}

	// Set up signal handler for clean unmount.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- bazilfs.Serve(c, NewFS(bridge, readOnly))
	}()

	select {
	case <-sigCh:
		_ = bazil.Unmount(mountpoint)
		<-serveDone
	case err = <-serveDone:
	}

	signal.Stop(sigCh)
	c.Close()
	return err
}

// Unmount unmounts the filesystem at mountpoint.
func Unmount(mountpoint string) error {
	return bazil.Unmount(mountpoint)
}
