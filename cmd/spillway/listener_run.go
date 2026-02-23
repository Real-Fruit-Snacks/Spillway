//go:build !agent

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Real-Fruit-Snacks/Spillway/internal/config"
	"github.com/Real-Fruit-Snacks/Spillway/internal/fuse"
	"github.com/Real-Fruit-Snacks/Spillway/internal/listener"
)

// Catppuccin Mocha palette — raw ANSI escape codes, no external dependency.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[38;2;243;139;168m" // Red
	colorGreen  = "\033[38;2;166;227;161m" // Green
	colorYellow = "\033[38;2;249;226;175m" // Yellow
	colorBlue   = "\033[38;2;137;180;250m" // Blue
	colorMauve  = "\033[38;2;203;166;247m" // Mauve
	colorTeal   = "\033[38;2;148;226;213m" // Teal
	colorText   = "\033[38;2;205;214;244m" // Text
	colorDim    = "\033[38;2;147;153;178m" // Overlay1
)

func printBanner() {
	fmt.Println(colorBlue + "╔═══════════════════════╗" + colorReset)
	fmt.Println(colorBlue + "║" + colorMauve + "      Spillway         " + colorBlue + "║" + colorReset)
	fmt.Println(colorBlue + "║" + colorDim + "   Reverse FUSE Mount  " + colorBlue + "║" + colorReset)
	fmt.Println(colorBlue + "╚═══════════════════════╝" + colorReset)
}

func printUsage() {
	printBanner()
	fmt.Println()
	fmt.Println(colorText + "Usage:" + colorReset)
	fmt.Println("  " + colorMauve + "spillway listen" + colorReset + colorDim + "   [flags]          — wait for agent connections" + colorReset)
	fmt.Println("  " + colorMauve + "spillway connect" + colorReset + colorDim + "  HOST:PORT [flags] — connect to agent" + colorReset)
	fmt.Println("  " + colorMauve + "spillway status" + colorReset + colorDim + "                    — show session info" + colorReset)
	fmt.Println("  " + colorMauve + "spillway unmount" + colorReset + colorDim + "  MOUNTPOINT        — unmount a session" + colorReset)
	fmt.Println()
	fmt.Println(colorText + "Flags (listen):" + colorReset)
	fmt.Println("  " + colorTeal + "-p, --port" + colorReset + "      port to listen on (default 4444)")
	fmt.Println("  " + colorTeal + "-m, --mount" + colorReset + "     mount point (default ./mnt)")
	fmt.Println("  " + colorTeal + "-k, --key" + colorReset + "       pre-shared key (base64)")
	fmt.Println("  " + colorTeal + "-r, --read-only" + colorReset + " mount read-only")
	fmt.Println("  " + colorTeal + "--cert" + colorReset + "          TLS certificate PEM file")
	fmt.Println("  " + colorTeal + "--key-file" + colorReset + "      TLS private key PEM file")
	fmt.Println()
	fmt.Println(colorText + "Flags (connect):" + colorReset)
	fmt.Println("  " + colorTeal + "-m, --mount" + colorReset + "     mount point (default ./mnt)")
	fmt.Println("  " + colorTeal + "-k, --key" + colorReset + "       pre-shared key (base64)")
	fmt.Println("  " + colorTeal + "-r, --read-only" + colorReset + " mount read-only")
}

// runAgent is a stub in the !agent build. cfgMode is always "" here so this
// function is never reachable from main, but it must exist because main.go
// references it unconditionally.
func runAgent() error { return nil }

func runListener() error {
	if len(os.Args) < 2 {
		printUsage()
		return nil
	}

	switch os.Args[1] {
	case "listen":
		return cmdListen(os.Args[2:])
	case "connect":
		return cmdConnect(os.Args[2:])
	case "status":
		return cmdStatus()
	case "unmount":
		return cmdUnmount(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
}

func cmdListen(args []string) error {
	fs := flag.NewFlagSet("listen", flag.ContinueOnError)

	var port int
	var mount, pskB64, certFile, keyFile string
	var readOnly bool

	fs.IntVar(&port, "port", 4444, "port to listen on")
	fs.IntVar(&port, "p", 4444, "port to listen on (shorthand)")
	fs.StringVar(&mount, "mount", "./mnt", "mount point")
	fs.StringVar(&mount, "m", "./mnt", "mount point (shorthand)")
	fs.StringVar(&pskB64, "key", "", "pre-shared key (base64)")
	fs.StringVar(&pskB64, "k", "", "pre-shared key (base64) (shorthand)")
	fs.BoolVar(&readOnly, "read-only", false, "mount read-only")
	fs.BoolVar(&readOnly, "r", false, "mount read-only (shorthand)")
	fs.StringVar(&certFile, "cert", "", "TLS certificate PEM file")
	fs.StringVar(&keyFile, "key-file", "", "TLS private key PEM file")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if pskB64 == "" {
		return fmt.Errorf("--key is required (base64-encoded PSK from build output)")
	}
	psk, err := decodePSK(pskB64)
	if err != nil {
		return fmt.Errorf("invalid PSK: %w", err)
	}

	certPEM, keyPEM, err := loadCertFiles(certFile, keyFile)
	if err != nil {
		return err
	}

	cfg := &config.ListenerConfig{
		Mode:       "reverse",
		ListenAddr: fmt.Sprintf(":%d", port),
		MountPoint: mount,
		PSK:        psk,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		ReadOnly:   readOnly,
		CacheTTL:   5,
	}

	printBanner()
	fmt.Printf("%s[*]%s Listening on %s:%d%s\n", colorGreen, colorReset, colorTeal, port, colorReset)
	fmt.Printf("%s[*]%s Mount point: %s%s%s\n", colorGreen, colorReset, colorMauve, mount, colorReset)
	if readOnly {
		fmt.Printf("%s[*]%s Mode: %sread-only%s\n", colorYellow, colorReset, colorYellow, colorReset)
	}

	return runWithSignal(cfg)
}

func cmdConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)

	var mount, pskB64 string
	var readOnly bool

	fs.StringVar(&mount, "mount", "./mnt", "mount point")
	fs.StringVar(&mount, "m", "./mnt", "mount point (shorthand)")
	fs.StringVar(&pskB64, "key", "", "pre-shared key (base64)")
	fs.StringVar(&pskB64, "k", "", "pre-shared key (base64) (shorthand)")
	fs.BoolVar(&readOnly, "read-only", false, "mount read-only")
	fs.BoolVar(&readOnly, "r", false, "mount read-only (shorthand)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("connect requires HOST:PORT argument")
	}
	addr := fs.Arg(0)

	if pskB64 == "" {
		return fmt.Errorf("--key is required (base64-encoded PSK from build output)")
	}
	psk, err := decodePSK(pskB64)
	if err != nil {
		return fmt.Errorf("invalid PSK: %w", err)
	}

	cfg := &config.ListenerConfig{
		Mode:        "bind",
		ConnectAddr: addr,
		MountPoint:  mount,
		PSK:         psk,
		ReadOnly:    readOnly,
		CacheTTL:    5,
	}

	printBanner()
	fmt.Printf("%s[*]%s Connecting to %s%s%s\n", colorGreen, colorReset, colorTeal, addr, colorReset)
	fmt.Printf("%s[*]%s Mount point: %s%s%s\n", colorGreen, colorReset, colorMauve, mount, colorReset)
	if readOnly {
		fmt.Printf("%s[*]%s Mode: %sread-only%s\n", colorYellow, colorReset, colorYellow, colorReset)
	}

	return runWithSignal(cfg)
}

func cmdStatus() error {
	// Sessions live within the running process; there is no persistent daemon.
	fmt.Printf("%s[*]%s No persistent daemon — sessions live within the running process.\n", colorDim, colorReset)
	fmt.Printf("%sTip:%s use 'ls <mountpoint>' to verify an active mount.\n", colorYellow, colorReset)
	return nil
}

func cmdUnmount(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("unmount requires a mount point argument")
	}
	mountpoint := args[0]

	fmt.Printf("%s[*]%s Unmounting %s%s%s\n", colorYellow, colorReset, colorMauve, mountpoint, colorReset)

	if err := fuse.Unmount(mountpoint); err != nil {
		return fmt.Errorf("unmount %s: %w", mountpoint, err)
	}

	fmt.Printf("%s[+]%s Unmounted %s%s%s\n", colorGreen, colorReset, colorMauve, mountpoint, colorReset)
	return nil
}

// runWithSignal creates a Listener, runs it, and stops cleanly on SIGINT/SIGTERM.
func runWithSignal(cfg *config.ListenerConfig) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	l := listener.New(cfg)

	errCh := make(chan error, 1)
	go func() {
		errCh <- l.Run(ctx)
	}()

	select {
	case <-ctx.Done():
		fmt.Printf("\n%s[*]%s Shutting down\n", colorYellow, colorReset)
		l.Stop()
		return nil
	case err := <-errCh:
		if err != nil {
			fmt.Printf("%s[!]%s %v\n", colorRed, colorReset, err)
		}
		return err
	}
}

// decodePSK base64-decodes pskB64. An empty string returns nil (no PSK).
func decodePSK(pskB64 string) ([]byte, error) {
	if pskB64 == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(pskB64)
}

// loadCertFiles reads PEM files from disk when paths are provided.
func loadCertFiles(certFile, keyFile string) (certPEM, keyPEM []byte, err error) {
	if certFile == "" && keyFile == "" {
		return nil, nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, nil, fmt.Errorf("both --cert and --key-file must be provided together")
	}
	certPEM, err = os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert file: %w", err)
	}
	keyPEM, err = os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read key file: %w", err)
	}
	return certPEM, keyPEM, nil
}
