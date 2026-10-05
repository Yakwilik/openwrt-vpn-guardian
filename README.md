# OpenWrt VPN Guardian

OpenWrt VPN Guardian is a selective VPN control plane for OpenWrt with v2rayA as the VPN backend.

Its main invariant is that ordinary direct traffic does not depend on VPN health. Only traffic matched by the selective routing rules enters the VPN path.

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

The single *vpn-guardian* Go binary provides stack management, watchdog, collector, self-test, dashboard UI and dashboard API. Xray remains the packet-routing engine and v2rayA remains the VPN backend.

## Features

- Stable Xray front router with TPROXY.
- Selective routing by geosite domains and explicit IP ranges.
- Direct traffic remains available when the VPN backend is unhealthy.
- VPN-only and fail-open policies for the proxy class.
- Automatic failover across multiple v2rayA subscriptions.
- VLESS TCP + Reality, VLESS XHTTP + Reality, VLESS WS + TLS, Hysteria2 and Shadowsocks candidates.
- Node scoring, EWMA latency and exponential cooldown.
- Pinned-node and automatic selection modes.
- Four independent backend health probes with healthy/degraded/down states.
- Embedded dashboard with status, history, events, nodes and subscriptions.
- Declarative manifests with validation, backup and rollback.
- Automatic first-run bootstrap.

## Installation

The package is intended to require only:

~~~sh
opkg install vpn-guardian_*.ipk
~~~

The post-install bootstrap automatically:

1. Detects the LAN interface, LAN CIDR/address and WAN interface.
2. Creates router-specific manifests under /etc/vpn-guardian.
3. Validates generated Xray and nftables configuration.
4. Enables v2rayA and switches it to backend-only mode.
5. Starts the embedded dashboard/API server.
6. Adds vpn.home.arpa to dnsmasq when dnsmasq is present.
7. Integrates with an existing nginx installation when nginx is present.
8. Generates the Xray front/policy, TPROXY routing, watchdog and collector configuration.
9. Creates a pre-apply backup.
10. Activates the stack, runs the self-test and enables boot services only after validation succeeds.

If v2rayA has no usable VPN node yet, bootstrap deliberately leaves the front inactive. The dashboard remains available so a subscription can be configured, and the bootstrap service retries automatically.

A read-only preflight is available:

~~~sh
vpn-guardian bootstrap --dry-run
~~~

## Dashboard

The dashboard is embedded into the Go binary.

Without any external web server it is available directly on the router LAN:

~~~text
http://<router-lan-ip>:20175/
~~~

When nginx is already installed, the package adds a small reverse-proxy virtual host and the same dashboard is available as:

~~~text
http://vpn.home.arpa/
~~~

nginx is optional and is not an OpenWrt package dependency.

## Runtime dependencies

The OpenWrt package depends only on components that are not reasonably replaced by a small amount of application code:

- *v2raya* — VPN backend and subscription/node management.
- *xray-core* — front and policy proxy engine.
- *v2ray-geosite* — geosite datasets used by selective routing.
- *ca-bundle* — CA roots for HTTPS health checks.
- *ip-full* — policy routing operations required by TPROXY.
- *nftables-json* — nftables userspace CLI used to validate and apply the front ruleset.
- *kmod-nft-tproxy* — kernel TPROXY support; it pulls its nftables/core dependencies.

Not required:

- nginx — optional integration only.
- fcgiwrap/CGI — the dashboard API is native Go HTTP.
- v2ray-geoip — no geoip rules are used.
- kmod-nft-socket — the generated front rules do not use the nft socket expression.

## Commands

~~~text
vpn-guardian bootstrap [--dry-run]
vpn-guardian status
vpn-guardian validate
vpn-guardian apply
vpn-guardian backup
vpn-guardian restore <archive>
vpn-guardian selftest
vpn-guardian watchdog [flags]
vpn-guardian collector -mode collect -interval 3s
vpn-guardian control [flags]
vpn-guardian api-server [-listen 0.0.0.0:20175]
~~~

## Configuration

Runtime manifests:

~~~text
/etc/vpn-guardian/stack.json
/etc/vpn-guardian/routing.json
/etc/vpn-guardian/control.json
~~~

The first two are generated from the router during bootstrap instead of shipping router-specific interface names or IP addresses.

Generic examples live under *configs/* and are also included in the package under */usr/share/vpn-guardian/examples/*.

## Build model

The binary is pure Go and OpenWrt builds it with:

~~~text
CGO_ENABLED=0
internal Go linker
target GOOS/GOARCH supplied by the OpenWrt SDK
~~~

CI additionally cross-builds static Linux binaries for:

- 386
- amd64
- arm
- arm64
- loong64
- riscv64

MIPS and MIPS64 are deliberately excluded because the current pure-Go SQLite dependency does not support those targets in this configuration.

The reference package target is:

~~~text
OpenWrt 24.10.4
mediatek/filogic
aarch64_cortex-a53
GL.iNet GL-MT6000
~~~

The OpenWrt SDK/IPK workflow is intentionally disabled during active development. CI currently runs tests, vet and CGO-free static cross-builds only. The package workflow will be re-enabled for the release phase, where it must build the exact Git commit with the matching official OpenWrt SDK and verify that the packaged binary has no dynamic dependencies.

## Safety model

Direct traffic must continue to work when v2rayA is restarting, unhealthy or unavailable.

When the VPN backend fails in VPN-only mode, the proxy class fails closed while direct traffic continues through the front. If the shared front itself fails, interception is retained until automatic recovery; it must not be bypassed silently. Local management remains outside interception.

Every apply creates a backup before replacing runtime configuration. A failed restart, self-test or service-enable step rolls back both files and runtime state. On a clean first install, rollback removes generated TPROXY state and restores ordinary routing.

## Development status

The unified binary, embedded dashboard/API, backend-only v2rayA bootstrap, collector, watchdog, self-test and OpenWrt package recipe are implemented.

Before the first tagged release the package must pass the SDK build, controlled install, reboot, upgrade and rollback checklist on the reference GL-MT6000.

See *docs/architecture.md* and *docs/release-checklist.md*.
