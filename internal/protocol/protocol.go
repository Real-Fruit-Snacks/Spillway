// Package protocol defines the Spillway wire protocol.
//
// Wire format: [4-byte frame length][1-byte type][4-byte request ID][type-specific payload]
// Variable-length fields: [4-byte length][data]
// All integers are big-endian.
package protocol

const (
	// ProtocolVersion is the current wire protocol version.
	ProtocolVersion byte = 1

	// MaxFrameSize limits individual frames to 16 MiB.
	MaxFrameSize = 16 << 20 // 16 MiB

	// HeaderSize is type (1) + request ID (4).
	HeaderSize = 5
)

// Message types — requests from listener to agent.
const (
	MsgStat      byte = 0x01
	MsgReadDir   byte = 0x02
	MsgReadFile  byte = 0x03
	MsgReadLink  byte = 0x04
	MsgWriteFile byte = 0x05
	MsgMkdir     byte = 0x06
	MsgRemove    byte = 0x07
	MsgRename    byte = 0x08
	MsgChmod     byte = 0x09
	MsgCreate    byte = 0x0A
	MsgTruncate  byte = 0x0B
	MsgGetXattr  byte = 0x0C
	MsgListXattr byte = 0x0D
)

// Message types — responses from agent to listener.
const (
	MsgStatResp      byte = 0x81
	MsgReadDirResp   byte = 0x82
	MsgReadFileResp  byte = 0x83
	MsgReadLinkResp  byte = 0x84
	MsgWriteFileResp byte = 0x85
	MsgMkdirResp     byte = 0x86
	MsgRemoveResp    byte = 0x87
	MsgRenameResp    byte = 0x88
	MsgChmodResp     byte = 0x89
	MsgCreateResp    byte = 0x8A
	MsgTruncateResp  byte = 0x8B
	MsgGetXattrResp  byte = 0x8C
	MsgListXattrResp byte = 0x8D
)

// Control message types.
const (
	MsgPing     byte = 0xF0
	MsgPong     byte = 0xF1
	MsgAuth     byte = 0xF2
	MsgAuthResp byte = 0xF3
	MsgError    byte = 0xFF
)
