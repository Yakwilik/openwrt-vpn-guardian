# OpenWrt VPN Guardian

OpenWrt VPN Guardian is a selective VPN control plane for OpenWrt routers with v2rayA as the VPN backend.

The project keeps ordinary direct traffic independent from VPN health. Only configured proxy traffic is sent through the VPN backend.

## Architecture

~~~text
LAN
 |
vpn-front
 |-- direct traffic ------------> WAN
 |
 '-- proxy class
       |
       v
    vpn-policy
       |
       v
    v2rayA SOCKS
       |
       v
    VPN node
~~~

## Current features

- Stable Xray front router with TPROXY.
- Selective routing by geosite domains and IP ranges.
- v2rayA in backend-only mode with transparent routing disabled.
- Automatic failover across multiple v2rayA subscriptions.
- Node scoring, EWMA latency and exponential cooldown.
- Pinned-node and automatic selection modes.
- VPN-only and fail-open failure policies.
- Multi-provider health checks with degraded/down states.
- Dashboard with nodes, subscriptions, health history and failover events.
- Isolated self-test for direct/proxy invariants.
- Declarative manifests with validate, apply, backup and rollback.

## Unified binary

The project is being migrated to one binary: *vpn-guardian*.

~~~text
vpn-guardian status
vpn-guardian validate
vpn-guardian apply
vpn-guardian backup
vpn-guardian restore <archive>
vpn-guardian selftest
vpn-guardian watchdog -mode daemon
vpn-guardian control -mode auto
~~~

For migration compatibility the same binary can be installed under the legacy names:

~~~text
vpn-stack
vpn-selftest
vpn-backend-watchdog
v2raya-failover
~~~

The command is selected from the executable name, so symlinks are sufficient.

## Build

~~~bash
go test ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o vpn-guardian ./cmd/vpn-guardian
~~~
## Configuration

Copy the example manifests and adapt them to the router:

~~~bash
mkdir -p /etc/vpn-stack
cp configs/stack.example.json /etc/vpn-stack/stack.json
cp configs/routing.example.json /etc/vpn-stack/routing.json
vpn-guardian validate
~~~

The current manifest format is version 1.

## Safety invariant

Direct traffic must continue to work when v2rayA is unhealthy, restarting or completely unavailable.

In VPN-only mode proxy traffic has no direct fallback. An unhealthy VPN backend therefore fails closed without requiring a global LAN blackhole.

The emergency blackhole policy remains available as an internal guard, but ordinary health degradation does not switch the whole proxy class to blackhole.

## Project status

The current code is an alpha extraction from a running OpenWrt installation. Core watchdog, stack manager, self-test and v2rayA control logic already build as one binary.

Dashboard status/control collector migration and the final OpenWrt package are the next milestones.

See *docs/architecture.md* and *docs/migration.md*.
