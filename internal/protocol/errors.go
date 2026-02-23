package protocol

import (
	"os"
	"syscall"
)

// Protocol error strings returned in response Error fields.
const (
	ErrOK         = ""
	ErrNotFound   = "ENOENT"
	ErrPermission = "EACCES"
	ErrExist      = "EEXIST"
	ErrNotDir     = "ENOTDIR"
	ErrIsDir      = "EISDIR"
	ErrNotEmpty   = "ENOTEMPTY"
	ErrIO         = "EIO"
	ErrInval      = "EINVAL"
	ErrNoSys      = "ENOSYS"
	ErrNoDat      = "ENODATA"
	ErrRange      = "ERANGE"
	ErrJail       = "EPERM"
	ErrReadOnly   = "EROFS"
)

// ToErrno maps a protocol error string to a syscall.Errno.
func ToErrno(e string) syscall.Errno {
	switch e {
	case ErrOK:
		return 0
	case ErrNotFound:
		return syscall.ENOENT
	case ErrPermission:
		return syscall.EACCES
	case ErrExist:
		return syscall.EEXIST
	case ErrNotDir:
		return syscall.ENOTDIR
	case ErrIsDir:
		return syscall.EISDIR
	case ErrNotEmpty:
		return syscall.ENOTEMPTY
	case ErrIO:
		return syscall.EIO
	case ErrInval:
		return syscall.EINVAL
	case ErrNoSys:
		return syscall.ENOSYS
	case ErrNoDat:
		return syscall.ENODATA
	case ErrRange:
		return syscall.ERANGE
	case ErrJail:
		return syscall.EPERM
	case ErrReadOnly:
		return syscall.EROFS
	default:
		return syscall.EIO
	}
}

// FromOSError converts an OS error to a protocol error string.
func FromOSError(err error) string {
	if err == nil {
		return ErrOK
	}
	// Extract the underlying syscall errno first for precise mapping.
	// This must happen before os.IsExist which conflates EEXIST and ENOTEMPTY.
	if pe, ok := err.(*os.PathError); ok {
		return fromSyscallErrno(pe.Err)
	}
	if le, ok := err.(*os.LinkError); ok {
		return fromSyscallErrno(le.Err)
	}
	if se, ok := err.(*os.SyscallError); ok {
		return fromSyscallErrno(se.Err)
	}
	// Fall back to broad os.Is* checks for non-wrapped errors.
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	if os.IsPermission(err) {
		return ErrPermission
	}
	if os.IsExist(err) {
		return ErrExist
	}
	return ErrIO
}

func fromSyscallErrno(err error) string {
	if errno, ok := err.(syscall.Errno); ok {
		switch errno {
		case syscall.ENOENT:
			return ErrNotFound
		case syscall.EACCES:
			return ErrPermission
		case syscall.EEXIST:
			return ErrExist
		case syscall.ENOTDIR:
			return ErrNotDir
		case syscall.EISDIR:
			return ErrIsDir
		case syscall.ENOTEMPTY:
			return ErrNotEmpty
		case syscall.EINVAL:
			return ErrInval
		case syscall.ENOSYS:
			return ErrNoSys
		case syscall.ENODATA:
			return ErrNoDat
		case syscall.ERANGE:
			return ErrRange
		case syscall.EPERM:
			return ErrJail
		case syscall.EROFS:
			return ErrReadOnly
		}
	}
	return ErrIO
}
