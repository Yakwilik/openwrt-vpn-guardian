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
