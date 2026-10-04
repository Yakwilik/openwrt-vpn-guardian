package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/control"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/selftest"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/stack"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/watchdog"
)

func main() {
	args := os.Args[1:]

	switch filepath.Base(os.Args[0]) {
	case "vpn-backend-watchdog":
		watchdog.Run(args)
		return
	case "vpn-stack":
		stack.Run(args)
		return
	case "vpn-selftest":
		selftest.Run(args)
		return
	case "v2raya-failover":
		control.Run(args)
		return
	}

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
	case "status", "validate", "apply", "backup", "restore":
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
	fmt.Fprintln(os.Stderr, "  vpn-guardian status|validate|apply|backup|restore <archive>")
	fmt.Fprintln(os.Stderr, "  vpn-guardian selftest")
	fmt.Fprintln(os.Stderr, "  vpn-guardian watchdog [legacy watchdog flags]")
	fmt.Fprintln(os.Stderr, "  vpn-guardian control [legacy control flags]")
}
