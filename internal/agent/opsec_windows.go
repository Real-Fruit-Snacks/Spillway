//go:build windows

package agent

import "os"

func disableCoreDumps() {}

func masqueradeProcess(name string) {}

func selfDeleteBinary() {
	// Best-effort: on Windows the running binary is locked, so this will
	// usually fail. We attempt it anyway for completeness.
	if len(os.Args) > 0 {
		_ = os.Remove(os.Args[0])
	}
}

func silenceOutput() {}
