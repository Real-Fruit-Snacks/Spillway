# Changelog

All notable changes to Spillway will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-04

### Added
- Reverse, bind, and dormant FUSE filesystem mount modes
- Full FUSE integration via `bazil.org/fuse` with 17 filesystem operations
- TLS 1.3 encrypted transport with ephemeral self-signed certificates
- Mutual HMAC-SHA256 PSK authentication (2-round challenge-response)
- Custom binary wire protocol with length-prefixed framing
- ClientMux/ServerMux request-response multiplexing (64 concurrent workers)
- Path jailing with symlink-aware resolution and configurable exclude lists
- Agent opsec: process masquerade, core dump prevention, self-delete, stdout silencing
- Dormant mode with AF_PACKET knock listener for knock-to-reverse activation
- HTTP CONNECT proxy tunneling with optional Basic authentication
- Token bucket rate limiter for bandwidth control
- TTL cache for stat and directory entries (5s expiry, 30s eviction)
- Compile-time configuration injection via `-ldflags -X` (zero runtime args)
- Cross-compilation for 5 platforms (linux/windows/darwin, amd64/arm64)
- Build script with auto PSK generation, SNI selection, UPX compression
- 133 tests covering protocol, transport, agent, FUSE, and listener
