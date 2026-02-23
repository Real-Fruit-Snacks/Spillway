package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolve_BasicPaths(t *testing.T) {
	jail := NewPathJail("/jail", nil)

	tests := []struct {
		name string
		path string
		want string
	}{
		{"root", "/", "/jail"},
		{"empty", "", "/jail"},
		{"simple file", "/etc/passwd", "/jail/etc/passwd"},
		{"nested", "/a/b/c/d", "/jail/a/b/c/d"},
		{"trailing slash", "/etc/", "/jail/etc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jail.Resolve(tt.path)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tt.path, err)
			}
			if got != tt.want {
				t.Errorf("Resolve(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestResolve_DotDotEscape(t *testing.T) {
	root := t.TempDir()
	jail := NewPathJail(root, nil)

	tests := []struct {
		name string
		path string
	}{
		{"simple dotdot", "/../../../etc/passwd"},
		{"mid dotdot", "/a/b/../../../.."},
		{"double dotdot", "/a/../../.."},
		{"dot slash dotdot", "/./../../.."},
		{"encoded-ish", "/.."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jail.Resolve(tt.path)
			if err != nil {
				// ErrJail is acceptable — the jail blocked it.
				return
			}
			// If no error, the resolved path MUST be under root.
			if got != root && !hasPrefix(got, root+string(filepath.Separator)) {
				t.Errorf("Resolve(%q) = %q escaped jail %q", tt.path, got, root)
			}
		})
	}
}

func TestResolve_SymlinkEscape(t *testing.T) {
	root := t.TempDir()

	// Create root/subdir and a symlink root/escape -> /
	subdir := filepath.Join(root, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	escapeLink := filepath.Join(root, "escape")
	if err := os.Symlink("/", escapeLink); err != nil {
		t.Fatal(err)
	}

	jail := NewPathJail(root, nil)

	_, err := jail.Resolve("/escape/etc/passwd")
	if err == nil {
		t.Error("expected ErrJail for symlink escape, got nil")
	}
}

func TestResolve_SymlinkInsideJail(t *testing.T) {
	root := t.TempDir()

	// Create root/a/real and root/b -> root/a (symlink within jail).
	realDir := filepath.Join(root, "a", "real")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "b")); err != nil {
		t.Fatal(err)
	}

	jail := NewPathJail(root, nil)

	got, err := jail.Resolve("/b/real")
	if err != nil {
		t.Fatalf("Resolve(/b/real): %v", err)
	}
	// Should resolve to root/a/real.
	want := filepath.Join(root, "a", "real")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolve_NonExistentPath(t *testing.T) {
	root := t.TempDir()
	jail := NewPathJail(root, nil)

	// Path that doesn't exist but parent does — should still resolve within jail.
	got, err := jail.Resolve("/nonexistent/file.txt")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := filepath.Join(root, "nonexistent", "file.txt")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolve_NonExistentParent(t *testing.T) {
	root := t.TempDir()
	jail := NewPathJail(root, nil)

	// Neither parent nor child exists — still should resolve safely.
	got, err := jail.Resolve("/deep/nested/path/file.txt")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := filepath.Join(root, "deep", "nested", "path", "file.txt")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolve_DotDotInSymlink(t *testing.T) {
	root := t.TempDir()

	// Create root/a/file.txt
	if err := os.MkdirAll(filepath.Join(root, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "file.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create root/b -> ../  (relative symlink that goes up)
	if err := os.Symlink("..", filepath.Join(root, "b")); err != nil {
		t.Fatal(err)
	}

	jail := NewPathJail(root, nil)

	// /b resolves to parent of root — should be blocked.
	_, err := jail.Resolve("/b/etc/passwd")
	if err == nil {
		t.Error("expected ErrJail for dotdot symlink escape")
	}
}

func TestResolve_JailRootItself(t *testing.T) {
	root := t.TempDir()
	jail := NewPathJail(root, nil)

	got, err := jail.Resolve("/")
	if err != nil {
		t.Fatalf("Resolve(/): %v", err)
	}
	if got != root {
		t.Errorf("got %q, want %q", got, root)
	}
}

func TestResolve_RootWithTrailingSlash(t *testing.T) {
	root := t.TempDir()
	// NewPathJail cleans the root, so trailing slash should be stripped.
	jail := NewPathJail(root+"/", nil)

	got, err := jail.Resolve("/test")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := filepath.Join(filepath.Clean(root), "test")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// --- Exclude tests ---

func TestIsExcluded(t *testing.T) {
	jail := NewPathJail("/jail", []string{"/proc", "/sys", "/dev"})

	tests := []struct {
		path string
		want bool
	}{
		{"/proc", true},
		{"/proc/1/status", true},
		{"/sys", true},
		{"/sys/class/net", true},
		{"/dev", true},
		{"/dev/null", true},
		{"/etc", false},
		{"/home", false},
		{"/proc-fake", false}, // Must not match prefix without separator.
		{"/system", false},    // /sys should not match /system.
		{"/developer", false}, // /dev should not match /developer.
	}
	for _, tt := range tests {
		got := jail.IsExcluded(tt.path)
		if got != tt.want {
			t.Errorf("IsExcluded(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsExcluded_NoExcludes(t *testing.T) {
	jail := NewPathJail("/jail", nil)
	if jail.IsExcluded("/proc") {
		t.Error("should not exclude when no excludes configured")
	}
}

func TestIsExcluded_EmptyExcludes(t *testing.T) {
	jail := NewPathJail("/jail", []string{})
	if jail.IsExcluded("/proc") {
		t.Error("should not exclude with empty excludes list")
	}
}

// --- Windows path normalization tests ---

func TestNormalizeWindowsPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`C:\Users\Admin`, "/C:/Users/Admin"},
		{`C:\`, "/C:/"},
		{`D:\Program Files\app`, "/D:/Program Files/app"},
		{"/unix/path", "/unix/path"},       // Unix paths unchanged.
		{"relative/path", "relative/path"}, // Relative paths unchanged.
		{`mixed/path\with\backslash`, "mixed/path/with/backslash"},
	}
	for _, tt := range tests {
		got := normalizeWindowsPath(tt.input)
		if got != tt.want {
			t.Errorf("normalizeWindowsPath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestResolve_WindowsDriveLetter(t *testing.T) {
	root := t.TempDir()
	jail := NewPathJail(root, nil)

	// A Windows-style path should be resolved under the jail, not escape to C:.
	got, err := jail.Resolve(`C:\Users\Admin\secrets.txt`)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Should be under root, not under C:\.
	if !hasPrefix(got, root) {
		t.Errorf("Windows path escaped jail: %q not under %q", got, root)
	}
}

// --- Concurrent access test ---

func TestResolve_Concurrent(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "b"), 0755); err != nil {
		t.Fatal(err)
	}
	jail := NewPathJail(root, nil)

	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			var path string
			if n%2 == 0 {
				path = "/a/file.txt"
			} else {
				path = "/b/file.txt"
			}
			_, err := jail.Resolve(path)
			if err != nil {
				t.Errorf("concurrent Resolve(%q): %v", path, err)
			}
		}(i)
	}
	for i := 0; i < 100; i++ {
		<-done
	}
}

// --- Helper ---

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
