//go:build agent

package main

import (
	"context"
	"encoding/base64"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Real-Fruit-Snacks/Spillway/internal/agent"
)

// runListener is a stub in the agent build. cfgMode is always set so this
// function is never reachable from main, but it must exist because main.go
// references it unconditionally.
func runListener() error { return nil }

func runAgent() error {
	psk, err := base64.StdEncoding.DecodeString(cfgPSK)
	if err != nil {
		return err
	}

	root := cfgRoot
	if root == "" {
		root = "/"
	}

	var excludes []string
	if cfgExcludes != "" {
		excludes = strings.Split(cfgExcludes, ",")
	}

	selfDelete := cfgSelfDelete == "true"

	rateLimit := 0.0
	if cfgRateLimit != "" {
		rateLimit, _ = strconv.ParseFloat(cfgRateLimit, 64)
	}
	rateBurst := 0
	if cfgRateBurst != "" {
		rateBurst, _ = strconv.Atoi(cfgRateBurst)
	}

	var delay time.Duration
	if cfgDelay != "" && cfgDelay != "0" {
		delaySec, _ := strconv.Atoi(cfgDelay)
		if delaySec > 0 {
			delay = time.Duration(delaySec) * time.Second
		}
	}

	var knockPort uint16
	if cfgKnockPort != "" {
		kp, _ := strconv.Atoi(cfgKnockPort)
		knockPort = uint16(kp)
	}

	cfg := agent.Config{
		Mode:           cfgMode,
		Address:        cfgAddress,
		PSK:            psk,
		TLSFingerprint: cfgFingerprint,
		SNI:            cfgSNI,
		Root:           root,
		Excludes:       excludes,
		ProcName:       cfgProcName,
		SelfDelete:     selfDelete,
		RateLimit:      rateLimit,
		RateBurst:      rateBurst,
		ProxyAddr:      cfgProxyAddr,
		ProxyUser:      cfgProxyUser,
		ProxyPass:      cfgProxyPass,
		ReadOnly:       cfgReadOnly == "true",
		Delay:          delay,
		KnockPort:      knockPort,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	a := agent.New(cfg)
	return a.Run(ctx)
}
