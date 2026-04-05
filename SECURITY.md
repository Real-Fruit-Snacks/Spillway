# Security Policy

## Supported Versions

Only the latest release of Spillway is supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < latest | :x:               |

## Reporting a Vulnerability

**Do NOT open public issues for security vulnerabilities.**

If you discover a security vulnerability in Spillway, please report it responsibly:

1. **Preferred:** Use [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Spillway/security/advisories/new) to create a private report.
2. **Alternative:** Email the maintainers directly with details of the vulnerability.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours of receipt
- **Assessment:** Within 7 days
- **Fix & Disclosure:** Within 90 days (coordinated responsible disclosure)

We follow a 90-day responsible disclosure timeline. If a fix is not released within 90 days, the reporter may disclose the vulnerability publicly.

## What is NOT a Vulnerability

Spillway is a penetration testing tool designed for authorized security assessments. The following behaviors are **features, not bugs**:

- Reverse, bind, and dormant FUSE filesystem mounting
- Encrypted communications (TLS 1.3 with PSK authentication)
- Process name masquerade and opsec hardening
- Binary self-delete capability
- Path jailing and filesystem access controls
- HTTP CONNECT proxy tunneling
- Rate-limited bandwidth control
- Dormant mode with knock-to-connect activation

These capabilities exist by design for legitimate security testing. Reports that simply describe Spillway working as intended will be closed.

## Responsible Use

Spillway is intended for authorized penetration testing, security research, and educational purposes only. Users are responsible for ensuring they have proper authorization before using this tool against any systems.
