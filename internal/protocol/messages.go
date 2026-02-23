package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	ErrFrameTooLarge = errors.New("frame exceeds maximum size")
	ErrTruncated     = errors.New("truncated message")
	ErrBadType       = errors.New("unknown message type")
)

// FileStat represents file metadata.
type FileStat struct {
	Name       string
	Size       int64
	Mode       uint32
	ModTime    int64 // Unix seconds
	IsDir      bool
	IsLink     bool
	LinkTarget string
	Uid        uint32
	Gid        uint32
}

// DirEntry is a single directory entry.
type DirEntry struct {
	Name  string
	IsDir bool
	Mode  uint32
}

// StatfsInfo holds filesystem statistics.
type StatfsInfo struct {
	TotalBlocks uint64
	FreeBlocks  uint64
	AvailBlocks uint64
	TotalInodes uint64
	FreeInodes  uint64
	BlockSize   uint32
	MaxNameLen  uint32
}

// Request is a protocol request from listener to agent.
type Request struct {
	Type      byte
	ID        uint32
	Path      string
	Path2     string // Rename destination
	Data      []byte // WriteFile data
	Offset    int64  // ReadFile offset
	Size      int64  // ReadFile size
	Mode      uint32 // Chmod/Create mode
	XattrName string // GetXattr name
	Uid       uint32 // Chown uid
	Gid       uint32 // Chown gid
}

// Response is a protocol response from agent to listener.
type Response struct {
	Type    byte
	ID      uint32
	Error   string
	Stat    *FileStat
	Entries []DirEntry
	Data    []byte
	Names   []string        // ListXattr result
	Written int64           // WriteFile bytes written
	Statfs  *StatfsInfo     // Statfs result
}

// --- Binary reader helper ---

type reader struct {
	buf []byte
	pos int
}

func newReader(data []byte) *reader {
	return &reader{buf: data}
}

func (r *reader) remaining() int {
	return len(r.buf) - r.pos
}

func (r *reader) readByte() (byte, error) {
	if r.remaining() < 1 {
		return 0, ErrTruncated
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *reader) readUint32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, ErrTruncated
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *reader) readInt64() (int64, error) {
	if r.remaining() < 8 {
		return 0, ErrTruncated
	}
	v := int64(binary.BigEndian.Uint64(r.buf[r.pos:]))
	r.pos += 8
	return v, nil
}

func (r *reader) readUint64() (uint64, error) {
	if r.remaining() < 8 {
		return 0, ErrTruncated
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, nil
}

func (r *reader) readString() (string, error) {
	length, err := r.readUint32()
	if err != nil {
		return "", err
	}
	if length > MaxFrameSize {
		return "", ErrFrameTooLarge
	}
	n := int(length)
	if r.remaining() < n {
		return "", ErrTruncated
	}
	s := string(r.buf[r.pos : r.pos+n])
	r.pos += n
	return s, nil
}

func (r *reader) readBytes() ([]byte, error) {
	length, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if length > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	n := int(length)
	if r.remaining() < n {
		return nil, ErrTruncated
	}
	b := make([]byte, n)
	copy(b, r.buf[r.pos:r.pos+n])
	r.pos += n
	return b, nil
}

func (r *reader) readBool() (bool, error) {
	b, err := r.readByte()
	if err != nil {
		return false, err
	}
	return b != 0, nil
}

// --- Binary writer helper ---

type writer struct {
	buf []byte
}

func newWriter(capacity int) *writer {
	return &writer{buf: make([]byte, 0, capacity)}
}

func (w *writer) writeByte(b byte) {
	w.buf = append(w.buf, b)
}

func (w *writer) writeUint32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

func (w *writer) writeInt64(v int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	w.buf = append(w.buf, b[:]...)
}

func (w *writer) writeUint64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

func (w *writer) writeString(s string) {
	w.writeUint32(uint32(len(s)))
	w.buf = append(w.buf, s...)
}

func (w *writer) writeBytes(data []byte) {
	w.writeUint32(uint32(len(data)))
	w.buf = append(w.buf, data...)
}

func (w *writer) writeBool(b bool) {
	if b {
		w.buf = append(w.buf, 1)
	} else {
		w.buf = append(w.buf, 0)
	}
}

func (w *writer) bytes() []byte {
	return w.buf
}

// --- Marshal / Unmarshal ---

// MarshalRequest encodes a Request into wire format (without frame length prefix).
func MarshalRequest(req *Request) []byte {
	w := newWriter(64)
	w.writeByte(req.Type)
	w.writeUint32(req.ID)
	w.writeString(req.Path)

	switch req.Type {
	case MsgRename:
		w.writeString(req.Path2)
	case MsgReadFile:
		w.writeInt64(req.Offset)
		w.writeInt64(req.Size)
	case MsgWriteFile:
		w.writeInt64(req.Offset)
		w.writeBytes(req.Data)
	case MsgChmod:
		w.writeUint32(req.Mode)
	case MsgCreate:
		w.writeUint32(req.Mode)
	case MsgTruncate:
		w.writeInt64(req.Size)
	case MsgGetXattr:
		w.writeString(req.XattrName)
	case MsgChown:
		w.writeUint32(req.Uid)
		w.writeUint32(req.Gid)
	case MsgSymlink:
		w.writeString(req.Path2)
	case MsgLink:
		w.writeString(req.Path2)
	}

	return w.bytes()
}

// UnmarshalRequest decodes a Request from wire format (without frame length prefix).
func UnmarshalRequest(data []byte) (*Request, error) {
	r := newReader(data)

	typ, err := r.readByte()
	if err != nil {
		return nil, err
	}
	id, err := r.readUint32()
	if err != nil {
		return nil, err
	}

	req := &Request{Type: typ, ID: id}

	// Control messages have no path.
	if typ == MsgPing || typ == MsgPong {
		return req, nil
	}

	req.Path, err = r.readString()
	if err != nil {
		return nil, err
	}

	switch typ {
	case MsgRename:
		req.Path2, err = r.readString()
	case MsgReadFile:
		req.Offset, err = r.readInt64()
		if err == nil {
			req.Size, err = r.readInt64()
		}
	case MsgWriteFile:
		req.Offset, err = r.readInt64()
		if err == nil {
			req.Data, err = r.readBytes()
		}
	case MsgChmod:
		req.Mode, err = r.readUint32()
	case MsgCreate:
		req.Mode, err = r.readUint32()
	case MsgTruncate:
		req.Size, err = r.readInt64()
	case MsgGetXattr:
		req.XattrName, err = r.readString()
	case MsgChown:
		req.Uid, err = r.readUint32()
		if err == nil {
			req.Gid, err = r.readUint32()
		}
	case MsgSymlink:
		req.Path2, err = r.readString()
	case MsgLink:
		req.Path2, err = r.readString()
	}
	if err != nil {
		return nil, err
	}

	return req, nil
}

// MarshalResponse encodes a Response into wire format.
func MarshalResponse(resp *Response) []byte {
	w := newWriter(128)
	w.writeByte(resp.Type)
	w.writeUint32(resp.ID)
	w.writeString(resp.Error)

	if resp.Error != "" {
		return w.bytes()
	}

	switch resp.Type {
	case MsgStatResp:
		marshalFileStat(w, resp.Stat)
	case MsgReadDirResp:
		w.writeUint32(uint32(len(resp.Entries)))
		for _, e := range resp.Entries {
			w.writeString(e.Name)
			w.writeBool(e.IsDir)
			w.writeUint32(e.Mode)
		}
	case MsgReadFileResp:
		w.writeBytes(resp.Data)
	case MsgReadLinkResp:
		if resp.Stat != nil {
			w.writeString(resp.Stat.LinkTarget)
		}
	case MsgWriteFileResp:
		w.writeInt64(resp.Written)
	case MsgGetXattrResp:
		w.writeBytes(resp.Data)
	case MsgListXattrResp:
		w.writeUint32(uint32(len(resp.Names)))
		for _, name := range resp.Names {
			w.writeString(name)
		}
	case MsgStatfsResp:
		if resp.Statfs == nil {
			w.writeByte(0)
		} else {
			w.writeByte(1)
			w.writeUint64(resp.Statfs.TotalBlocks)
			w.writeUint64(resp.Statfs.FreeBlocks)
			w.writeUint64(resp.Statfs.AvailBlocks)
			w.writeUint64(resp.Statfs.TotalInodes)
			w.writeUint64(resp.Statfs.FreeInodes)
			w.writeUint32(resp.Statfs.BlockSize)
			w.writeUint32(resp.Statfs.MaxNameLen)
		}
	case MsgAuthResp:
		w.writeBytes(resp.Data)
		// MsgMkdirResp, MsgRemoveResp, MsgRenameResp, MsgChmodResp, MsgCreateResp, MsgTruncateResp,
		// MsgChownResp, MsgSymlinkResp, MsgLinkResp: no extra payload beyond error.
	}

	return w.bytes()
}

// UnmarshalResponse decodes a Response from wire format.
func UnmarshalResponse(data []byte) (*Response, error) {
	r := newReader(data)

	typ, err := r.readByte()
	if err != nil {
		return nil, err
	}
	id, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	errStr, err := r.readString()
	if err != nil {
		return nil, err
	}

	resp := &Response{Type: typ, ID: id, Error: errStr}

	if errStr != "" {
		return resp, nil
	}

	switch typ {
	case MsgPong:
		// No payload.
	case MsgStatResp:
		resp.Stat, err = unmarshalFileStat(r)
	case MsgReadDirResp:
		var count uint32
		count, err = r.readUint32()
		if err == nil {
			if count > MaxFrameSize/8 {
				return nil, ErrFrameTooLarge
			}
			resp.Entries = make([]DirEntry, count)
			for i := range resp.Entries {
				resp.Entries[i].Name, err = r.readString()
				if err != nil {
					break
				}
				resp.Entries[i].IsDir, err = r.readBool()
				if err != nil {
					break
				}
				resp.Entries[i].Mode, err = r.readUint32()
				if err != nil {
					break
				}
			}
		}
	case MsgReadFileResp:
		resp.Data, err = r.readBytes()
	case MsgReadLinkResp:
		var target string
		target, err = r.readString()
		if err == nil {
			resp.Stat = &FileStat{LinkTarget: target}
		}
	case MsgWriteFileResp:
		resp.Written, err = r.readInt64()
	case MsgGetXattrResp:
		resp.Data, err = r.readBytes()
	case MsgListXattrResp:
		var count uint32
		count, err = r.readUint32()
		if err == nil {
			if count > MaxFrameSize/4 {
				return nil, ErrFrameTooLarge
			}
			resp.Names = make([]string, count)
			for i := range resp.Names {
				resp.Names[i], err = r.readString()
				if err != nil {
					break
				}
			}
		}
	case MsgStatfsResp:
		var marker byte
		marker, err = r.readByte()
		if err == nil && marker != 0 {
			resp.Statfs = &StatfsInfo{}
			resp.Statfs.TotalBlocks, err = r.readUint64()
			if err == nil {
				resp.Statfs.FreeBlocks, err = r.readUint64()
			}
			if err == nil {
				resp.Statfs.AvailBlocks, err = r.readUint64()
			}
			if err == nil {
				resp.Statfs.TotalInodes, err = r.readUint64()
			}
			if err == nil {
				resp.Statfs.FreeInodes, err = r.readUint64()
			}
			if err == nil {
				resp.Statfs.BlockSize, err = r.readUint32()
			}
			if err == nil {
				resp.Statfs.MaxNameLen, err = r.readUint32()
			}
		}
	case MsgAuthResp:
		resp.Data, err = r.readBytes()
	}
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func marshalFileStat(w *writer, st *FileStat) {
	if st == nil {
		st = &FileStat{}
	}
	w.writeString(st.Name)
	w.writeInt64(st.Size)
	w.writeUint32(st.Mode)
	w.writeInt64(st.ModTime)
	w.writeBool(st.IsDir)
	w.writeBool(st.IsLink)
	w.writeString(st.LinkTarget)
	w.writeUint32(st.Uid)
	w.writeUint32(st.Gid)
}

func unmarshalFileStat(r *reader) (*FileStat, error) {
	st := &FileStat{}
	var err error
	st.Name, err = r.readString()
	if err != nil {
		return nil, err
	}
	st.Size, err = r.readInt64()
	if err != nil {
		return nil, err
	}
	st.Mode, err = r.readUint32()
	if err != nil {
		return nil, err
	}
	st.ModTime, err = r.readInt64()
	if err != nil {
		return nil, err
	}
	st.IsDir, err = r.readBool()
	if err != nil {
		return nil, err
	}
	st.IsLink, err = r.readBool()
	if err != nil {
		return nil, err
	}
	st.LinkTarget, err = r.readString()
	if err != nil {
		return nil, err
	}
	st.Uid, err = r.readUint32()
	if err != nil {
		return nil, err
	}
	st.Gid, err = r.readUint32()
	if err != nil {
		return nil, err
	}
	return st, nil
}

// ReadFrame reads a single length-prefixed frame from r.
func ReadFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, length)
	}
	frame := make([]byte, length)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

// WriteFrame writes a single length-prefixed frame to w as a single Write call
// to avoid interleaving when multiple goroutines share the same writer.
func WriteFrame(w io.Writer, data []byte) error {
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	_, err := w.Write(buf)
	return err
}
