//go:build !linux && !windows

package agent

func disableCoreDumps() {}

func masqueradeProcess(name string) {}

func selfDeleteBinary() {}

func silenceOutput() {}
