# Architecture

## Design goal

The VPN backend must never become a single point of failure for ordinary Internet access.

Direct traffic and proxy-class traffic are separated before v2rayA:

~~~text
client
  |
  v
vpn-front (Xray)
  |
  +-- direct class -> marked freedom outbound -> WAN
  |
  +-- proxy class -> vpn-policy -> 127.0.0.1:20173 -> v2rayA -> VPN
~~~

v2rayA is deliberately kept in backend-only mode with its transparent proxy disabled.

## vpn-front

*vpn-front* is a stable Xray process that owns the LAN TPROXY entry point.

The nftables prerouting rule intercepts LAN TCP/UDP traffic and sends it to vpn-front. Private/local destination ranges are bypassed before interception.

vpn-front classifies traffic using:

- geosite domain groups;
- explicit domain rules;
- explicit IP ranges.

Matched proxy traffic goes to vpn-policy. Everything else uses a marked direct Xray freedom socket so it bypasses the TPROXY rule on egress.

## vpn-policy

vpn-policy is a second Xray process listening only on loopback.

Public policy modes:

- *VPN-only* — proxy-class traffic stays bound to the v2rayA SOCKS backend and fails closed when the backend is unavailable.
- *Fail-open* — proxy-class traffic may temporarily fall back to direct Internet.
- *Direct* — explicit operator override; classification remains active but the proxy class is routed directly.

An internal emergency blocked configuration exists for invariant failures. Normal VPN health degradation does not activate a global LAN blackhole.

Policy switching is implemented in Go by atomically replacing the generated policy config, validating it with Xray and restarting only vpn-policy.

## v2rayA backend

v2rayA owns subscriptions, node definitions and the selected VPN connection.

vpn-guardian ensures:

~~~text
transparent = close
SOCKS backend = 127.0.0.1:20173
~~~

vpn-guardian reads v2rayA state and updates node selection through the local v2rayA API. Direct access to the SQLite database is used for local control metadata that v2rayA does not expose conveniently.

## Watchdog and failover

The watchdog probes four independent connectivity endpoints through the backend SOCKS listener.

Health states:

- *healthy* — 3 or 4 probes succeed;
- *degraded* — 2 probes succeed;
- *down* — 0 or 1 probe succeeds.

A down state must remain confirmed before failover.

Backend listener loss is handled before endpoint health probing. If a node is selected but the v2rayA SOCKS listener is absent, the watchdog first gives the manager a short grace window, then repairs backend-only state if needed and restarts v2rayA when the listener is still missing. The restart decision does not depend on the v2raya_core PID: a surviving core process with no SOCKS listener is treated as stuck. Automatic repair is rate-limited to avoid restart loops. While the listener is unavailable, watchdog state is written as down with 0/4 probes so the dashboard never displays stale healthy results.

Candidate eligibility is shared by watchdog, collector and control code. Current transports:

- VLESS TCP + Reality;
- VLESS XHTTP + Reality;
- VLESS WebSocket + TLS;
- Hysteria2;
- Shadowsocks.

Selection combines transport priority, EWMA latency, recent failures and exponential cooldown.

## Collector

The collector produces a cheap dashboard cache instead of making every UI refresh inspect v2rayA, nftables and external endpoints.

It records:

- current node/protocol/endpoint;
- direct and VPN egress IPs;
- health probe results;
- candidate count and total node count;
- stack/service state;
- policy mode;
- recent failures and switches;
- history samples.

The candidate count uses the same eligibility code as the watchdog, so *auto-selection* and *total nodes* cannot drift because of duplicated transport logic.

## Dashboard and API

The dashboard HTML is embedded into the vpn-guardian binary.

The native Go HTTP server exposes:

~~~text
/
 /healthz
 /api/status
 /api/history
 /api/control
~~~

Default listener:

~~~text
0.0.0.0:20175
~~~

OpenWrt firewall policy determines which router interfaces can reach it. The package does not open a WAN firewall rule.

When nginx is already installed, vpn.home.arpa is added as an optional reverse proxy to 127.0.0.1:20175. nginx is not required for the package to work.

Control mutations require a management session and CSRF token. Initial management unlock is accepted only from the LAN CIDR declared in the stack manifest. X-Real-IP is trusted only when the immediate HTTP peer is loopback, which allows a local reverse proxy without allowing direct clients to spoof their source.

## Bootstrap

The first-run bootstrap is intentionally ordered so an unconfigured VPN cannot break ordinary Internet access:

~~~text
discover interfaces
  -> create manifests
  -> render and validate
  -> start/prepare v2rayA backend-only
  -> start dashboard/API
  -> wait for usable VPN SOCKS backend
  -> backup
  -> apply front/policy/routing
  -> self-test
  -> enable boot services
~~~

If the VPN backend is not usable, bootstrap stops before front activation and retries later.

## Self-test

The self-test checks:

- nftables front table;
- policy rule and route table;
- absence of a global LAN blackhole;
- required services;
- direct egress;
- backend VPN egress;
- fail-open behavior with a dead backend;
- VPN-only fail-closed behavior;
- emergency blocked behavior.

The destructive policy checks use isolated temporary Xray instances instead of changing the production front.

## Backup and rollback

Apply follows:

~~~text
backup
  -> render
  -> validate
  -> atomic install
  -> restart
  -> self-test
  -> enable at boot
~~~

On failure:

- a previously active stack is restored from its snapshot and restarted;
- a clean first install removes generated TPROXY state and restores the sparse pre-apply snapshot.

Package-owned binaries and static init files are not part of runtime backups; package management owns those files.

## External runtime components

vpn-guardian intentionally keeps only the external components that would be unreasonable to reimplement as small application helpers:

- Xray for transparent proxy routing;
- v2rayA for VPN subscriptions/nodes;
- nftables and kernel TPROXY;
- Linux policy routing;
- CA roots;
- geosite data.

nginx and dnsmasq integrations are optional conveniences.


## Front recovery and operational boundaries

The front is a shared classifier for both traffic classes. Backend failure must not interrupt direct traffic. Front failure is different: when VPN-only is enabled, intercepted Internet traffic remains blocked until front recovery, rather than bypassing the classifier. Local/private destinations, including upstream management, are excluded from interception.

The watchdog passively checks the transparent listener through procfs. It never opens a test connection to the transparent port. Generated routing also rejects loopback destinations received through the transparent inbound as defense in depth.

The nftables ruleset is replaced in one transaction. A missing listener falls through to an explicit drop rule; a forward-chain guard prevents marked traffic from escaping through WAN if policy routing is incomplete. The watchdog restores missing VPN-only routing before restarting front. Fail-open remains an explicit operator policy, never an automatic override of VPN-only.

Daemon singleton locks and mutation locks have distinct lifetimes and distinct files. The watchdog holds the mutation lock only during one iteration. Dashboard mutations have a bounded lock wait. The self-test returns errors to its caller so deferred cleanup runs on failure.

Router-level acceptance tests under *tests/router/* use an isolated network namespace attached to the configured LAN bridge. They exercise DNS, HTTP dashboard access, direct/VPN separation, authenticated management, core shutdown through the v2rayA API, and front shutdown with interception retained. Fault injection must be run explicitly from an independent management network.
