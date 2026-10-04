package main

import (
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
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	switch args[0] {
	case "watchdog":
		watchdog.Run(args[1:])
	case "stack":
		stack.Run(args[1:])
	case "selftest":
		selftest.Run(args[1:])
	case "control":
		control.Run(args[1:])
	case "collector":
		collector.Run(args[1:])
	case "api-server":
		if err := api.Serve(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, "vpn-guardian api-server:", err)
			os.Exit(1)
		}
	case "bootstrap", "init", "status", "validate", "apply", "backup", "restore", "cleanup":
		stack.Run(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "vpn-guardian - selective VPN control plane for OpenWrt")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  vpn-guardian bootstrap [--dry-run]")
	fmt.Fprintln(os.Stderr, "  vpn-guardian init [--dry-run] [--force]")
	fmt.Fprintln(os.Stderr, "  vpn-guardian status|validate|apply|backup|restore <archive>")
	fmt.Fprintln(os.Stderr, "  vpn-guardian cleanup")
	fmt.Fprintln(os.Stderr, "  vpn-guardian selftest")
	fmt.Fprintln(os.Stderr, "  vpn-guardian watchdog [flags]")
	fmt.Fprintln(os.Stderr, "  vpn-guardian control [flags]")
	fmt.Fprintln(os.Stderr, "  vpn-guardian collector -mode collect -interval 3s")
	fmt.Fprintln(os.Stderr, "  vpn-guardian api-server [-listen 0.0.0.0:20175]")
}
