package protocol

import (
	"bytes"
	"os"
	"reflect"
	"syscall"
	"testing"
)

// --- Request round-trip tests ---

func TestRequestRoundTrip_Stat(t *testing.T) {
	req := &Request{Type: MsgStat, ID: 42, Path: "/etc/passwd"}
	got := roundTripRequest(t, req)
	assertEqual(t, "Type", got.Type, MsgStat)
	assertEqual(t, "ID", got.ID, uint32(42))
	assertEqual(t, "Path", got.Path, "/etc/passwd")
}

func TestRequestRoundTrip_ReadDir(t *testing.T) {
	req := &Request{Type: MsgReadDir, ID: 1, Path: "/var/log"}
	got := roundTripRequest(t, req)
	assertEqual(t, "Path", got.Path, "/var/log")
}

func TestRequestRoundTrip_ReadFile(t *testing.T) {
	req := &Request{Type: MsgReadFile, ID: 7, Path: "/data/file.bin", Offset: 1024, Size: 4096}
	got := roundTripRequest(t, req)
	assertEqual(t, "Path", got.Path, "/data/file.bin")
	assertEqual(t, "Offset", got.Offset, int64(1024))
	assertEqual(t, "Size", got.Size, int64(4096))
}

func TestRequestRoundTrip_ReadLink(t *testing.T) {
	req := &Request{Type: MsgReadLink, ID: 3, Path: "/usr/bin/python"}
	got := roundTripRequest(t, req)
	assertEqual(t, "Path", got.Path, "/usr/bin/python")
}

func TestRequestRoundTrip_WriteFile(t *testing.T) {
	data := []byte("hello world")
	req := &Request{Type: MsgWriteFile, ID: 9, Path: "/tmp/out", Offset: 512, Data: data}
	got := roundTripRequest(t, req)
	assertEqual(t, "Path", got.Path, "/tmp/out")
	assertEqual(t, "Offset", got.Offset, int64(512))
	if !bytes.Equal(got.Data, data) {
		t.Errorf("Data: got %q, want %q", got.Data, data)
	}
}

func TestRequestRoundTrip_Mkdir(t *testing.T) {
	req := &Request{Type: MsgMkdir, ID: 10, Path: "/tmp/newdir"}
	got := roundTripRequest(t, req)
	assertEqual(t, "Path", got.Path, "/tmp/newdir")
}

func TestRequestRoundTrip_Remove(t *testing.T) {
	req := &Request{Type: MsgRemove, ID: 11, Path: "/tmp/old"}
	got := roundTripRequest(t, req)
	assertEqual(t, "Path", got.Path, "/tmp/old")
}

func TestRequestRoundTrip_Rename(t *testing.T) {
	req := &Request{Type: MsgRename, ID: 12, Path: "/a/b", Path2: "/c/d"}
	got := roundTripRequest(t, req)
	assertEqual(t, "Path", got.Path, "/a/b")
	assertEqual(t, "Path2", got.Path2, "/c/d")
}

func TestRequestRoundTrip_Chmod(t *testing.T) {
	req := &Request{Type: MsgChmod, ID: 13, Path: "/file", Mode: 0755}
	got := roundTripRequest(t, req)
	assertEqual(t, "Mode", got.Mode, uint32(0755))
}

func TestRequestRoundTrip_Create(t *testing.T) {
	req := &Request{Type: MsgCreate, ID: 14, Path: "/new", Mode: 0644}
	got := roundTripRequest(t, req)
	assertEqual(t, "Path", got.Path, "/new")
	assertEqual(t, "Mode", got.Mode, uint32(0644))
}

func TestRequestRoundTrip_Truncate(t *testing.T) {
	req := &Request{Type: MsgTruncate, ID: 15, Path: "/file", Size: 100}
	got := roundTripRequest(t, req)
	assertEqual(t, "Size", got.Size, int64(100))
}

func TestRequestRoundTrip_GetXattr(t *testing.T) {
	req := &Request{Type: MsgGetXattr, ID: 16, Path: "/file", XattrName: "user.foo"}
	got := roundTripRequest(t, req)
	assertEqual(t, "XattrName", got.XattrName, "user.foo")
}

func TestRequestRoundTrip_ListXattr(t *testing.T) {
	req := &Request{Type: MsgListXattr, ID: 17, Path: "/file"}
	got := roundTripRequest(t, req)
	assertEqual(t, "Path", got.Path, "/file")
}

func TestRequestRoundTrip_Ping(t *testing.T) {
	req := &Request{Type: MsgPing, ID: 99}
	got := roundTripRequest(t, req)
	assertEqual(t, "Type", got.Type, MsgPing)
	assertEqual(t, "ID", got.ID, uint32(99))
	assertEqual(t, "Path", got.Path, "") // Ping has no path.
}

func TestRequestRoundTrip_Pong(t *testing.T) {
	req := &Request{Type: MsgPong, ID: 100}
	got := roundTripRequest(t, req)
	assertEqual(t, "Type", got.Type, MsgPong)
	assertEqual(t, "ID", got.ID, uint32(100))
}

// --- Response round-trip tests ---

func TestResponseRoundTrip_Stat(t *testing.T) {
	st := &FileStat{
		Name: "passwd", Size: 2048, Mode: 0644, ModTime: 1700000000,
		IsDir: false, IsLink: false, LinkTarget: "", Uid: 0, Gid: 0,
	}
	resp := &Response{Type: MsgStatResp, ID: 1, Stat: st}
	got := roundTripResponse(t, resp)
	if got.Stat == nil {
		t.Fatal("Stat is nil")
	}
	assertEqual(t, "Stat.Name", got.Stat.Name, "passwd")
	assertEqual(t, "Stat.Size", got.Stat.Size, int64(2048))
	assertEqual(t, "Stat.Mode", got.Stat.Mode, uint32(0644))
	assertEqual(t, "Stat.ModTime", got.Stat.ModTime, int64(1700000000))
	assertEqual(t, "Stat.IsDir", got.Stat.IsDir, false)
	assertEqual(t, "Stat.Uid", got.Stat.Uid, uint32(0))
}

func TestResponseRoundTrip_StatDir(t *testing.T) {
	st := &FileStat{
		Name: "etc", Size: 4096, Mode: 0755 | uint32(os.ModeDir), ModTime: 1700000000,
		IsDir: true, IsLink: false, Uid: 0, Gid: 0,
	}
	resp := &Response{Type: MsgStatResp, ID: 2, Stat: st}
	got := roundTripResponse(t, resp)
	assertEqual(t, "Stat.IsDir", got.Stat.IsDir, true)
	assertEqual(t, "Stat.Name", got.Stat.Name, "etc")
}

func TestResponseRoundTrip_StatSymlink(t *testing.T) {
	st := &FileStat{
		Name: "python", Size: 0, Mode: 0777, ModTime: 1700000000,
		IsDir: false, IsLink: true, LinkTarget: "/usr/bin/python3",
		Uid: 0, Gid: 0,
	}
	resp := &Response{Type: MsgStatResp, ID: 3, Stat: st}
	got := roundTripResponse(t, resp)
	assertEqual(t, "Stat.IsLink", got.Stat.IsLink, true)
	assertEqual(t, "Stat.LinkTarget", got.Stat.LinkTarget, "/usr/bin/python3")
}

func TestResponseRoundTrip_ReadDir(t *testing.T) {
	entries := []DirEntry{
		{Name: "file1.txt", IsDir: false, Mode: 0644},
		{Name: "subdir", IsDir: true, Mode: 0755},
		{Name: "link", IsDir: false, Mode: 0777},
	}
	resp := &Response{Type: MsgReadDirResp, ID: 5, Entries: entries}
	got := roundTripResponse(t, resp)
	if len(got.Entries) != 3 {
		t.Fatalf("Entries: got %d, want 3", len(got.Entries))
	}
	for i, want := range entries {
		assertEqual(t, "Name", got.Entries[i].Name, want.Name)
		assertEqual(t, "IsDir", got.Entries[i].IsDir, want.IsDir)
		assertEqual(t, "Mode", got.Entries[i].Mode, want.Mode)
	}
}

func TestResponseRoundTrip_ReadDirEmpty(t *testing.T) {
	resp := &Response{Type: MsgReadDirResp, ID: 6, Entries: []DirEntry{}}
	got := roundTripResponse(t, resp)
	if len(got.Entries) != 0 {
		t.Fatalf("Entries: got %d, want 0", len(got.Entries))
	}
}

func TestResponseRoundTrip_ReadFile(t *testing.T) {
	data := []byte("file contents here\nline two\n")
	resp := &Response{Type: MsgReadFileResp, ID: 7, Data: data}
	got := roundTripResponse(t, resp)
	if !bytes.Equal(got.Data, data) {
		t.Errorf("Data: got %q, want %q", got.Data, data)
	}
}

func TestResponseRoundTrip_ReadFileEmpty(t *testing.T) {
	resp := &Response{Type: MsgReadFileResp, ID: 8, Data: []byte{}}
	got := roundTripResponse(t, resp)
	if len(got.Data) != 0 {
		t.Errorf("Data: got len %d, want 0", len(got.Data))
	}
}

func TestResponseRoundTrip_ReadLink(t *testing.T) {
	resp := &Response{Type: MsgReadLinkResp, ID: 9, Stat: &FileStat{LinkTarget: "/usr/bin/python3"}}
	got := roundTripResponse(t, resp)
	if got.Stat == nil {
		t.Fatal("Stat is nil")
	}
	assertEqual(t, "LinkTarget", got.Stat.LinkTarget, "/usr/bin/python3")
}

func TestResponseRoundTrip_WriteFile(t *testing.T) {
	resp := &Response{Type: MsgWriteFileResp, ID: 10, Written: 1024}
	got := roundTripResponse(t, resp)
	assertEqual(t, "Written", got.Written, int64(1024))
}

func TestResponseRoundTrip_GetXattr(t *testing.T) {
	data := []byte("xattr-value")
	resp := &Response{Type: MsgGetXattrResp, ID: 11, Data: data}
	got := roundTripResponse(t, resp)
	if !bytes.Equal(got.Data, data) {
		t.Errorf("Data: got %q, want %q", got.Data, data)
	}
}

func TestResponseRoundTrip_ListXattr(t *testing.T) {
	names := []string{"user.foo", "user.bar", "security.selinux"}
	resp := &Response{Type: MsgListXattrResp, ID: 12, Names: names}
	got := roundTripResponse(t, resp)
	if !reflect.DeepEqual(got.Names, names) {
		t.Errorf("Names: got %v, want %v", got.Names, names)
	}
}

func TestResponseRoundTrip_ListXattrEmpty(t *testing.T) {
	resp := &Response{Type: MsgListXattrResp, ID: 13, Names: []string{}}
	got := roundTripResponse(t, resp)
	if len(got.Names) != 0 {
		t.Errorf("Names: got len %d, want 0", len(got.Names))
	}
}

func TestResponseRoundTrip_ErrorResponse(t *testing.T) {
	resp := &Response{Type: MsgStatResp, ID: 20, Error: ErrNotFound}
	got := roundTripResponse(t, resp)
	assertEqual(t, "Error", got.Error, ErrNotFound)
	if got.Stat != nil {
		t.Error("Stat should be nil for error response")
	}
}

func TestResponseRoundTrip_SuccessNoPayload(t *testing.T) {
	// MsgMkdirResp, MsgRemoveResp, etc. have no payload beyond error.
	for _, typ := range []byte{MsgMkdirResp, MsgRemoveResp, MsgRenameResp, MsgChmodResp, MsgCreateResp, MsgTruncateResp} {
		resp := &Response{Type: typ, ID: 30}
		got := roundTripResponse(t, resp)
		assertEqual(t, "Type", got.Type, typ)
		assertEqual(t, "Error", got.Error, "")
	}
}

func TestResponseRoundTrip_Pong(t *testing.T) {
	resp := &Response{Type: MsgPong, ID: 50}
	got := roundTripResponse(t, resp)
	assertEqual(t, "Type", got.Type, MsgPong)
	assertEqual(t, "ID", got.ID, uint32(50))
}

// --- Frame read/write tests ---

func TestFrameRoundTrip(t *testing.T) {
	data := []byte("hello frame")
	var buf bytes.Buffer
	if err := WriteFrame(&buf, data); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestFrameRoundTrip_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte{}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got len %d, want 0", len(got))
	}
}

func TestFrameRoundTrip_LargePayload(t *testing.T) {
	data := bytes.Repeat([]byte("A"), 1<<20) // 1 MiB
	var buf bytes.Buffer
	if err := WriteFrame(&buf, data); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("large payload mismatch")
	}
}

func TestFrameRoundTrip_Multiple(t *testing.T) {
	var buf bytes.Buffer
	frames := [][]byte{[]byte("first"), []byte("second"), []byte("third")}
	for _, f := range frames {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}
	for _, want := range frames {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestReadFrame_Truncated(t *testing.T) {
	// Only 2 bytes of length prefix (need 4).
	buf := bytes.NewReader([]byte{0x00, 0x00})
	_, err := ReadFrame(buf)
	if err == nil {
		t.Error("expected error for truncated length")
	}
}

func TestReadFrame_TruncatedPayload(t *testing.T) {
	// Length says 10 bytes but only 3 available.
	data := []byte{0x00, 0x00, 0x00, 0x0A, 0x01, 0x02, 0x03}
	buf := bytes.NewReader(data)
	_, err := ReadFrame(buf)
	if err == nil {
		t.Error("expected error for truncated payload")
	}
}

// --- Unmarshal error cases ---

func TestUnmarshalRequest_Empty(t *testing.T) {
	_, err := UnmarshalRequest([]byte{})
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestUnmarshalRequest_TruncatedID(t *testing.T) {
	// Type byte present but ID truncated.
	_, err := UnmarshalRequest([]byte{MsgStat, 0x00})
	if err == nil {
		t.Error("expected error for truncated ID")
	}
}

func TestUnmarshalResponse_Empty(t *testing.T) {
	_, err := UnmarshalResponse([]byte{})
	if err == nil {
		t.Error("expected error for empty data")
	}
}

// --- Full message frame integration ---

func TestRequestFrameIntegration(t *testing.T) {
	req := &Request{Type: MsgWriteFile, ID: 77, Path: "/tmp/test", Offset: 100, Data: []byte("payload")}
	data := MarshalRequest(req)

	var buf bytes.Buffer
	if err := WriteFrame(&buf, data); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	frame, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	got, err := UnmarshalRequest(frame)
	if err != nil {
		t.Fatalf("UnmarshalRequest: %v", err)
	}
	assertEqual(t, "Type", got.Type, MsgWriteFile)
	assertEqual(t, "ID", got.ID, uint32(77))
	assertEqual(t, "Path", got.Path, "/tmp/test")
	assertEqual(t, "Offset", got.Offset, int64(100))
	if !bytes.Equal(got.Data, []byte("payload")) {
		t.Errorf("Data mismatch")
	}
}

func TestResponseFrameIntegration(t *testing.T) {
	resp := &Response{
		Type: MsgReadDirResp, ID: 88,
		Entries: []DirEntry{
			{Name: "a", IsDir: true, Mode: 0755},
			{Name: "b.txt", IsDir: false, Mode: 0644},
		},
	}
	data := MarshalResponse(resp)

	var buf bytes.Buffer
	if err := WriteFrame(&buf, data); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	frame, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	got, err := UnmarshalResponse(frame)
	if err != nil {
		t.Fatalf("UnmarshalResponse: %v", err)
	}
	assertEqual(t, "ID", got.ID, uint32(88))
	if len(got.Entries) != 2 {
		t.Fatalf("Entries: got %d, want 2", len(got.Entries))
	}
	assertEqual(t, "Entries[0].Name", got.Entries[0].Name, "a")
	assertEqual(t, "Entries[1].Name", got.Entries[1].Name, "b.txt")
}

// --- Error mapping tests ---

func TestToErrno(t *testing.T) {
	tests := []struct {
		input string
		want  syscall.Errno
	}{
		{ErrOK, 0},
		{ErrNotFound, syscall.ENOENT},
		{ErrPermission, syscall.EACCES},
		{ErrExist, syscall.EEXIST},
		{ErrNotDir, syscall.ENOTDIR},
		{ErrIsDir, syscall.EISDIR},
		{ErrNotEmpty, syscall.ENOTEMPTY},
		{ErrIO, syscall.EIO},
		{ErrInval, syscall.EINVAL},
		{ErrNoSys, syscall.ENOSYS},
		{ErrNoDat, syscall.ENODATA},
		{ErrRange, syscall.ERANGE},
		{ErrJail, syscall.EPERM},
		{ErrReadOnly, syscall.EROFS},
		{"UNKNOWN", syscall.EIO}, // default
	}
	for _, tt := range tests {
		got := ToErrno(tt.input)
		if got != tt.want {
			t.Errorf("ToErrno(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestFromOSError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ErrOK},
		{"not exist", os.ErrNotExist, ErrNotFound},
		{"permission", os.ErrPermission, ErrPermission},
		{"exist", os.ErrExist, ErrExist},
		{"path error ENOENT", &os.PathError{Op: "stat", Path: "/x", Err: syscall.ENOENT}, ErrNotFound},
		{"path error EISDIR", &os.PathError{Op: "write", Path: "/x", Err: syscall.EISDIR}, ErrIsDir},
		{"path error ENOTDIR", &os.PathError{Op: "open", Path: "/x", Err: syscall.ENOTDIR}, ErrNotDir},
		{"path error ENOTEMPTY", &os.PathError{Op: "rmdir", Path: "/x", Err: syscall.ENOTEMPTY}, ErrNotEmpty},
		{"link error", &os.LinkError{Op: "rename", Old: "/a", New: "/b", Err: syscall.EACCES}, ErrPermission},
		{"syscall error", &os.SyscallError{Syscall: "ioctl", Err: syscall.EINVAL}, ErrInval},
		{"unknown error", os.ErrClosed, ErrIO},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromOSError(tt.err)
			if got != tt.want {
				t.Errorf("FromOSError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

// --- Unicode / binary edge cases ---

func TestRequestRoundTrip_UnicodePath(t *testing.T) {
	req := &Request{Type: MsgStat, ID: 1, Path: "/tmp/日本語/ファイル.txt"}
	got := roundTripRequest(t, req)
	assertEqual(t, "Path", got.Path, "/tmp/日本語/ファイル.txt")
}

func TestResponseRoundTrip_BinaryData(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	resp := &Response{Type: MsgReadFileResp, ID: 1, Data: data}
	got := roundTripResponse(t, resp)
	if !bytes.Equal(got.Data, data) {
		t.Error("binary data mismatch")
	}
}

func TestRequestRoundTrip_EmptyPath(t *testing.T) {
	req := &Request{Type: MsgStat, ID: 1, Path: ""}
	got := roundTripRequest(t, req)
	assertEqual(t, "Path", got.Path, "")
}

func TestResponseRoundTrip_LargeDirectory(t *testing.T) {
	entries := make([]DirEntry, 1000)
	for i := range entries {
		entries[i] = DirEntry{Name: "file_" + string(rune('A'+i%26)), IsDir: i%3 == 0, Mode: 0644}
	}
	resp := &Response{Type: MsgReadDirResp, ID: 1, Entries: entries}
	got := roundTripResponse(t, resp)
	if len(got.Entries) != 1000 {
		t.Fatalf("Entries: got %d, want 1000", len(got.Entries))
	}
	for i, want := range entries {
		if got.Entries[i].Name != want.Name || got.Entries[i].IsDir != want.IsDir {
			t.Errorf("entry %d mismatch", i)
		}
	}
}

// --- Helpers ---

func roundTripRequest(t *testing.T, req *Request) *Request {
	t.Helper()
	data := MarshalRequest(req)
	got, err := UnmarshalRequest(data)
	if err != nil {
		t.Fatalf("UnmarshalRequest: %v", err)
	}
	return got
}

func roundTripResponse(t *testing.T, resp *Response) *Response {
	t.Helper()
	data := MarshalResponse(resp)
	got, err := UnmarshalResponse(data)
	if err != nil {
		t.Fatalf("UnmarshalResponse: %v", err)
	}
	return got
}

func assertEqual[T comparable](t *testing.T, name string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", name, got, want)
	}
}
