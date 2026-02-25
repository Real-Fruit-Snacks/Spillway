//go:build !agent

package agent

import "context"

// runDormant is a stub for the listener build. The dormant mode code path is
// only reachable in agent binaries (cfgMode is set at link time).
func (a *Agent) runDormant(_ context.Context) error {
	panic("dormant mode requires agent build tag")
}
