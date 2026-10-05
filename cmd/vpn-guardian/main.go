package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/api"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/collector"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/control"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/selftest"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/stack"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/watchdog"
)

func main() {
	args := os.Args
	if len(args) < 2 {
		usage()
		os.Exit(2)
	}

	if err := run(args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "vpn-guardian:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("command required")
	}

	command := args[0]
	commandArgs := args[1:]

	switch command {
	case "watchdog":
		watchdog.Run(commandArgs)
		return nil
	case "stack":
		return stack.Run(commandArgs)
	case "selftest":
		return selftest.Run(commandArgs)
	case "control":
		control.Run(commandArgs)
		return nil
	case "collector":
		collector.Run(commandArgs)
		return nil
	case "api-server":
		return api.Serve(commandArgs)
	case "bootstrap", "init", "status", "validate", "apply", "backup", "restore", "cleanup":
		return stack.Run(args)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "vpn-guardian - selective VPN control plane for OpenWrt")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  vpn-guardian bootstrap [--non-interactive] [--dry-run]")
	fmt.Fprintln(os.Stderr, "  vpn-guardian init [--non-interactive] [--dry-run]")
	fmt.Fprintln(os.Stderr, "  vpn-guardian status|validate|apply|backup|restore <archive>")
	fmt.Fprintln(os.Stderr, "  vpn-guardian cleanup")
	fmt.Fprintln(os.Stderr, "  vpn-guardian selftest")
	fmt.Fprintln(os.Stderr, "  vpn-guardian watchdog [flags]")
	fmt.Fprintln(os.Stderr, "  vpn-guardian control [flags]")
	fmt.Fprintln(os.Stderr, "  vpn-guardian collector -mode collect -interval 3s")
	fmt.Fprintln(os.Stderr, "  vpn-guardian api-server [-listen 0.0.0.0:20175]")
}
