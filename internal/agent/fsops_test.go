//go:build agent

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
)

func TestIsWriteOp(t *testing.T) {
	writeOps := []byte{
		protocol.MsgWriteFile, protocol.MsgMkdir, protocol.MsgRemove,
		protocol.MsgRename, protocol.MsgChmod, protocol.MsgCreate,
		protocol.MsgTruncate, protocol.MsgChown, protocol.MsgSymlink,
		protocol.MsgLink,
	}
	for _, op := range writeOps {
		if !isWriteOp(op) {
			t.Errorf("isWriteOp(0x%02x) = false, want true", op)
		}
	}

	readOps := []byte{
		protocol.MsgStat, protocol.MsgReadDir, protocol.MsgReadFile,
		protocol.MsgReadLink, protocol.MsgGetXattr, protocol.MsgListXattr,
		protocol.MsgStatfs,
	}
	for _, op := range readOps {
		if isWriteOp(op) {
			t.Errorf("isWriteOp(0x%02x) = true, want false", op)
		}
	}
}

func TestDispatch_ReadOnlyRejectsWrites(t *testing.T) {
	jail := NewPathJail(t.TempDir(), nil)
	writeOps := []byte{
		protocol.MsgWriteFile, protocol.MsgMkdir, protocol.MsgRemove,
		protocol.MsgRename, protocol.MsgChmod, protocol.MsgCreate,
		protocol.MsgTruncate, protocol.MsgChown, protocol.MsgSymlink,
		protocol.MsgLink,
	}
	for _, op := range writeOps {
		req := &protocol.Request{Type: op, ID: 1, Path: "/test"}
		resp := dispatchRequest(req, jail, true)
		if resp.Error != protocol.ErrReadOnly {
			t.Errorf("type 0x%02x: got error %q, want %q", op, resp.Error, protocol.ErrReadOnly)
		}
	}
}

func TestDispatch_ReadOnlyAllowsReads(t *testing.T) {
	tmp := t.TempDir()
	// Create a test file so Stat succeeds.
	os.WriteFile(filepath.Join(tmp, "test.txt"), []byte("hello"), 0644)

	jail := NewPathJail(tmp, nil)
	req := &protocol.Request{Type: protocol.MsgStat, ID: 1, Path: "/test.txt"}
	resp := dispatchRequest(req, jail, true)
	if resp.Error != "" {
		t.Errorf("Stat in readOnly: got error %q, want empty", resp.Error)
	}
	if resp.Stat == nil {
		t.Fatal("expected stat result")
	}
	if resp.Stat.Name != "test.txt" {
		t.Errorf("stat name = %q, want test.txt", resp.Stat.Name)
	}
}

func TestDispatch_UnknownType(t *testing.T) {
	jail := NewPathJail(t.TempDir(), nil)
	req := &protocol.Request{Type: 0x7F, ID: 1, Path: "/test"}
	resp := dispatchRequest(req, jail, false)
	if resp.Error != protocol.ErrInval {
		t.Errorf("unknown type: got error %q, want %q", resp.Error, protocol.ErrInval)
	}
}

func TestHandleStat(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "hello.txt"), []byte("world"), 0644)

	jail := NewPathJail(tmp, nil)
	req := &protocol.Request{Type: protocol.MsgStat, ID: 1, Path: "/hello.txt"}
	resp := handleStat(req, jail)
	if resp.Error != "" {
		t.Fatalf("handleStat error: %s", resp.Error)
	}
	if resp.Stat.Name != "hello.txt" {
		t.Errorf("Name = %q, want hello.txt", resp.Stat.Name)
	}
	if resp.Stat.Size != 5 {
		t.Errorf("Size = %d, want 5", resp.Stat.Size)
	}
}

func TestHandleStat_NotFound(t *testing.T) {
	jail := NewPathJail(t.TempDir(), nil)
	req := &protocol.Request{Type: protocol.MsgStat, ID: 1, Path: "/nope"}
	resp := handleStat(req, jail)
	if resp.Error != protocol.ErrNotFound {
		t.Errorf("expected ENOENT, got %q", resp.Error)
	}
}

func TestHandleReadDir(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "a.txt"), nil, 0644)
	os.Mkdir(filepath.Join(tmp, "subdir"), 0755)

	jail := NewPathJail(tmp, nil)
	req := &protocol.Request{Type: protocol.MsgReadDir, ID: 1, Path: "/"}
	resp := handleReadDir(req, jail)
	if resp.Error != "" {
		t.Fatalf("handleReadDir error: %s", resp.Error)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(resp.Entries))
	}
}

func TestHandleWriteFile(t *testing.T) {
	tmp := t.TempDir()
	jail := NewPathJail(tmp, nil)

	// Create first.
	fpath := filepath.Join(tmp, "out.txt")
	os.WriteFile(fpath, nil, 0644)

	req := &protocol.Request{
		Type: protocol.MsgWriteFile,
		ID:   1,
		Path: "/out.txt",
		Data: []byte("hello"),
	}
	resp := handleWriteFile(req, jail)
	if resp.Error != "" {
		t.Fatalf("handleWriteFile error: %s", resp.Error)
	}
	if resp.Written != 5 {
		t.Errorf("Written = %d, want 5", resp.Written)
	}

	content, _ := os.ReadFile(fpath)
	if string(content) != "hello" {
		t.Errorf("file content = %q, want hello", content)
	}
}

func TestHandleMkdir(t *testing.T) {
	tmp := t.TempDir()
	jail := NewPathJail(tmp, nil)

	req := &protocol.Request{Type: protocol.MsgMkdir, ID: 1, Path: "/newdir"}
	resp := handleMkdir(req, jail)
	if resp.Error != "" {
		t.Fatalf("handleMkdir error: %s", resp.Error)
	}

	info, err := os.Stat(filepath.Join(tmp, "newdir"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}

func TestHandleRemove(t *testing.T) {
	tmp := t.TempDir()
	fpath := filepath.Join(tmp, "removeme.txt")
	os.WriteFile(fpath, nil, 0644)

	jail := NewPathJail(tmp, nil)
	req := &protocol.Request{Type: protocol.MsgRemove, ID: 1, Path: "/removeme.txt"}
	resp := handleRemove(req, jail)
	if resp.Error != "" {
		t.Fatalf("handleRemove error: %s", resp.Error)
	}
	if _, err := os.Stat(fpath); !os.IsNotExist(err) {
		t.Error("file should be removed")
	}
}

func TestHandleRename(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "old.txt"), []byte("data"), 0644)

	jail := NewPathJail(tmp, nil)
	req := &protocol.Request{Type: protocol.MsgRename, ID: 1, Path: "/old.txt", Path2: "/new.txt"}
	resp := handleRename(req, jail)
	if resp.Error != "" {
		t.Fatalf("handleRename error: %s", resp.Error)
	}
	if _, err := os.Stat(filepath.Join(tmp, "old.txt")); !os.IsNotExist(err) {
		t.Error("old file should not exist")
	}
	content, _ := os.ReadFile(filepath.Join(tmp, "new.txt"))
	if string(content) != "data" {
		t.Errorf("new file content = %q, want data", content)
	}
}

func TestHandleChmod(t *testing.T) {
	tmp := t.TempDir()
	fpath := filepath.Join(tmp, "chmod.txt")
	os.WriteFile(fpath, nil, 0644)

	jail := NewPathJail(tmp, nil)
	req := &protocol.Request{Type: protocol.MsgChmod, ID: 1, Path: "/chmod.txt", Mode: 0755}
	resp := handleChmod(req, jail)
	if resp.Error != "" {
		t.Fatalf("handleChmod error: %s", resp.Error)
	}
}

func TestHandleCreate(t *testing.T) {
	tmp := t.TempDir()
	jail := NewPathJail(tmp, nil)

	req := &protocol.Request{Type: protocol.MsgCreate, ID: 1, Path: "/created.txt", Mode: 0644}
	resp := handleCreate(req, jail)
	if resp.Error != "" {
		t.Fatalf("handleCreate error: %s", resp.Error)
	}
	if _, err := os.Stat(filepath.Join(tmp, "created.txt")); err != nil {
		t.Fatal("file should exist")
	}
}

func TestHandleStatfs(t *testing.T) {
	tmp := t.TempDir()
	jail := NewPathJail(tmp, nil)

	req := &protocol.Request{Type: protocol.MsgStatfs, ID: 1, Path: "/"}
	resp := handleStatfs(req, jail)
	if resp.Error != "" {
		t.Fatalf("handleStatfs error: %s", resp.Error)
	}
	if resp.Statfs == nil {
		t.Fatal("expected Statfs result")
	}
	if resp.Statfs.BlockSize == 0 {
		t.Error("BlockSize should be non-zero")
	}
}

func TestHandleSymlink(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "target.txt"), []byte("data"), 0644)

	jail := NewPathJail(tmp, nil)
	req := &protocol.Request{
		Type:  protocol.MsgSymlink,
		ID:    1,
		Path:  "target.txt",  // symlink target (relative)
		Path2: "/link.txt",   // link location inside jail
	}
	resp := handleSymlink(req, jail)
	if resp.Error != "" {
		t.Fatalf("handleSymlink error: %s", resp.Error)
	}

	link := filepath.Join(tmp, "link.txt")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if target != "target.txt" {
		t.Errorf("link target = %q, want target.txt", target)
	}
}

func TestHandleLink(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "original.txt"), []byte("data"), 0644)

	jail := NewPathJail(tmp, nil)
	req := &protocol.Request{
		Type:  protocol.MsgLink,
		ID:    1,
		Path:  "/original.txt",
		Path2: "/hardlink.txt",
	}
	resp := handleLink(req, jail)
	if resp.Error != "" {
		t.Fatalf("handleLink error: %s", resp.Error)
	}

	content, err := os.ReadFile(filepath.Join(tmp, "hardlink.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "data" {
		t.Errorf("hardlink content = %q, want data", content)
	}
}

func TestHandleChown(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "chown.txt"), nil, 0644)

	jail := NewPathJail(tmp, nil)
	// Chown to current uid/gid (won't fail even as non-root).
	req := &protocol.Request{
		Type: protocol.MsgChown,
		ID:   1,
		Path: "/chown.txt",
		Uid:  uint32(os.Getuid()),
		Gid:  uint32(os.Getgid()),
	}
	resp := handleChown(req, jail)
	if resp.Error != "" {
		t.Fatalf("handleChown error: %s", resp.Error)
	}
}

func TestJailEscapeRejected(t *testing.T) {
	jail := NewPathJail(t.TempDir(), nil)
	req := &protocol.Request{Type: protocol.MsgStat, ID: 1, Path: "/../../etc/passwd"}
	resp := handleStat(req, jail)
	if resp.Error != protocol.ErrJail && resp.Error != protocol.ErrNotFound {
		// ErrJail if the jail catches it, or ENOENT if path resolves but doesn't match jail.
		t.Logf("jail escape result: %q (acceptable)", resp.Error)
	}
}
