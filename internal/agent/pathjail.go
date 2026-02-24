package agent

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
)

// ErrJail is returned when a resolved path escapes the jail root.
var ErrJail = errors.New(protocol.ErrJail)

// PathJail restricts filesystem access to a root directory.
type PathJail struct {
	root     string
	excludes []string
}

// NewPathJail creates a PathJail rooted at root. Excludes is a list of
// absolute path prefixes that are forbidden even within the root.
func NewPathJail(root string, excludes []string) *PathJail {
	cleaned := filepath.Clean(root)
	cleanedExcludes := make([]string, len(excludes))
	for i, e := range excludes {
		cleanedExcludes[i] = filepath.Clean(e)
	}
	return &PathJail{
		root:     cleaned,
		excludes: cleanedExcludes,
	}
}

// Resolve joins the jail root with remotePath, evaluates symlinks, and
// verifies the result is still inside the root. Returns ErrJail on escape.
//
// SECURITY: There is an inherent TOCTOU (time-of-check-to-time-of-use) race
// between path resolution and the subsequent filesystem operation. An attacker
// with write access inside the jail could swap a path component for a symlink
// after Resolve returns but before the caller opens the file. This limitation
// is inherent to all userspace path-jailing approaches and mirrors the
// behaviour of chroot(2) without pivot_root.
//
// Mitigations applied:
//   - EvalSymlinks at resolve time collapses existing symlink chains.
//   - Partial resolution handles not-yet-created paths safely.
//
// For stronger isolation, prefer OS-level namespaces (Linux mount namespaces)
// or openat2(2) with RESOLVE_BENEATH when available.
func (j *PathJail) Resolve(remotePath string) (string, error) {
	if remotePath == "" {
		return j.root, nil
	}

	remotePath = normalizeWindowsPath(remotePath)

	// Strip leading slash to make it relative before joining.
	cleaned := filepath.Clean("/" + remotePath)
	joined := filepath.Join(j.root, cleaned)

	// EvalSymlinks requires the path to exist. For paths that don't exist yet
	// (e.g. write targets) we walk up until we find an existing ancestor,
	// resolve symlinks on it, then re-append the non-existent tail.
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		resolved = resolvePartial(joined)
	}

	// Ensure the resolved path is under the jail root.
	// Append separator so /root doesn't match /rootother.
	jailPrefix := j.root
	if !strings.HasSuffix(jailPrefix, string(filepath.Separator)) {
		jailPrefix += string(filepath.Separator)
	}
	if resolved != j.root && !strings.HasPrefix(resolved, jailPrefix) {
		return "", ErrJail
	}

	return resolved, nil
}

// IsExcluded reports whether the resolved path starts with any exclude prefix.
func (j *PathJail) IsExcluded(path string) bool {
	for _, excl := range j.excludes {
		exclPrefix := excl
		if !strings.HasSuffix(exclPrefix, string(filepath.Separator)) {
			exclPrefix += string(filepath.Separator)
		}
		if path == excl || strings.HasPrefix(path, exclPrefix) {
			return true
		}
	}
	return false
}

// jailRelative strips the jail root prefix from an absolute path, returning
// a path relative to the jail root. Relative paths and paths outside the jail
// are returned unchanged.
func (j *PathJail) jailRelative(absPath string) string {
	if !filepath.IsAbs(absPath) {
		return absPath
	}
	rel, err := filepath.Rel(j.root, absPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return absPath
	}
	return "/" + rel
}

// resolvePartial walks up from path until it finds an existing ancestor,
// resolves symlinks on that ancestor, and re-appends the non-existent tail.
func resolvePartial(path string) string {
	var tail []string
	cur := path
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			// Found an existing ancestor — reconstruct with tail.
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return resolved
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			// Reached filesystem root without finding existing path.
			// Fall back to clean join.
			resolved = cur
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return resolved
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

// normalizeWindowsPath converts Windows-style paths to a form usable with
// filepath.Join on the current OS. On non-Windows hosts this is a no-op for
// unix paths but handles drive letters that a Windows agent might send.
func normalizeWindowsPath(p string) string {
	// Replace backslashes with forward slashes.
	p = strings.ReplaceAll(p, `\`, "/")

	// Convert drive letter "C:/..." → "/C:/..." so it is treated as absolute
	// within the jail rather than escaping to a Windows drive root.
	if len(p) >= 2 && p[1] == ':' {
		p = "/" + p
	}

	return p
}
