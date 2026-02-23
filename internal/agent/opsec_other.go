//go:build !linux && !windows && !darwin

package agent

func disableCoreDumps() {}

func masqueradeProcess(name string) {}

func selfDeleteBinary() {}

func silenceOutput() {}
