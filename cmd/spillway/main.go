package main

import (
	"fmt"
	"os"
)

func main() {
	if cfgMode != "" {
		// Agent mode — configuration was baked at compile time via -ldflags.
		if err := runAgent(); err != nil {
			os.Exit(1) // silent exit — no error output in agent mode
		}
		return
	}
	// Listener / CLI mode.
	if err := runListener(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
