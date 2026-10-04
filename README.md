# OpenWrt VPN Guardian

OpenWrt VPN Guardian is a selective VPN control plane for OpenWrt with v2rayA as the VPN backend.

The core invariant is simple: ordinary direct traffic is independent from VPN health. Only traffic matched by the selective routing rules is sent to the VPN backend.

## Architecture

~~~text
LAN
 |
vpn-front (Xray TPROXY)
 |-- direct class ----------------------> WAN
 |
 '-- proxy class
       |
       v
    vpn-policy
       |
       v
    v2rayA SOCKS 127.0.0.1:20173
       |
       v
    selected VPN node
~~~

v2rayA runs in backend-only mode with its own transparent proxy disabled.

## Features

- Stable Xray front router with TPROXY.
- Selective routing by geosite domains and IP ranges.
- Direct traffic remains available when the VPN backend is unhealthy.
- VPN-only and fail-open policies for the proxy class.
- Automatic failover across multiple v2rayA subscriptions.
- VLESS TCP + Reality, VLESS XHTTP + Reality, VLESS WS + TLS, Hysteria2 and Shadowsocks candidates.
- Node scoring, EWMA latency and exponential cooldown.
- Pinned-node and automatic selection modes.
- Multi-provider backend health checks with healthy/degraded/down states.
- Dashboard with status, health history, events, nodes and subscriptions.
- One unified Go binary for stack management, watchdog, collector, self-test and dashboard APIs.
- Declarative manifests with validation, backup, rollback and bootstrap.

## Unified binary

~~~text
vpn-guardian bootstrap [--dry-run]
vpn-guardian status
vpn-guardian validate
vpn-guardian apply
vpn-guardian backup
vpn-guardian restore <archive>
vpn-guardian selftest
vpn-guardian watchdog -mode daemon
vpn-guardian collector -mode collect -interval 3s
vpn-guardian control -mode auto
vpn-guardian api status|history|control
~~~

Compatibility symlinks are installed for the legacy command names:

~~~text
vpn-stack
vpn-selftest
vpn-backend-watchdog
vpn-status-collector
v2raya-failover
vpn-status
vpn-history
vpn-control
~~~

## First-run bootstrap

The OpenWrt package is designed to configure the stack automatically.

Bootstrap:

1. Detects the LAN interface, LAN CIDR/address and WAN interface.
2. Creates the version-1 stack and routing manifests if they do not exist.
3. Validates generated Xray and nftables configuration before activation.
4. Enables v2rayA and converts it to backend-only mode (transparent=close).
5. Configures local vpn.home.arpa DNS.
6. Starts the loopback-only native dashboard API service and reloads the nginx virtual host.
7. Generates the front, policy, policy-routing, watchdog and collector configuration.
8. Creates a pre-apply backup.
9. Activates the stack and runs the complete self-test.
10. Enables the services at boot only after the runtime passes validation.

If v2rayA does not yet have an active SOCKS backend, bootstrap leaves the front inactive and the bootstrap service retries in the background. Installing the package therefore does not make ordinary Internet access depend on an unconfigured VPN backend.

Before an upgrade or manual activation, the discovery path can be checked without persistent changes:

~~~sh
vpn-guardian bootstrap --dry-run
~~~

## OpenWrt package

The current package target used for GL.iNet GL-MT6000 testing is:

~~~text
OpenWrt 24.10.4
target: mediatek/filogic
architecture: aarch64_cortex-a53
~~~

The package recipe is in package/openwrt. The GitHub Actions package workflow builds the IPK from the current checkout using the official OpenWrt SDK.

A package install is intended to be enough:

~~~sh
opkg install vpn-guardian_*.ipk
~~~

The post-install hook starts the safe bootstrap service automatically. The package also migrates the legacy dashboard nginx virtual host out of the active config and preserves the legacy control CGI only when it is needed for PIN/session migration.

The Go binary is built with CGO disabled and internal linking. Dependencies are pinned to versions that build with Go 1.23.12, matching the OpenWrt 24.10 package feed. CGO-free builds are supported on 386, amd64, arm, arm64 and riscv64; MIPS/MIPS64 targets are deliberately excluded because modernc/sqlite does not support them in this configuration.

## Build the Go binary

~~~sh
GOTOOLCHAIN=go1.23.12 go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOTOOLCHAIN=go1.23.12 go build -trimpath -o vpn-guardian ./cmd/vpn-guardian
~~~

## Configuration

Runtime manifests live in:

~~~text
/etc/vpn-stack/stack.json
/etc/vpn-stack/routing.json
~~~

They are generated from the router on first install instead of shipping router-specific interface names or addresses inside the package.

Generic examples remain available in the repository under configs/.

## Safety model

Direct traffic must continue to work when v2rayA is restarting, unhealthy or completely unavailable.

In VPN-only mode only the proxy class fails closed. There is no global LAN blackhole.

Every apply creates a backup first. A failed restart, self-test or service-enable step rolls the runtime back as well as the files. On a clean first install a rollback also removes the front TPROXY rules and marker so ordinary routing is restored.

## Project status

The unified binary, collector, status/history/control API, bootstrap logic and OpenWrt package layout are implemented in the repository.

The remaining work before a tagged release is OpenWrt SDK package validation, controlled installation on the reference GL-MT6000, reboot/upgrade testing, and broader tests.

See docs/architecture.md and docs/migration.md.
