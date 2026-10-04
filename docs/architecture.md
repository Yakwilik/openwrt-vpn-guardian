# Architecture

## Design goal

The VPN backend is not allowed to become a single point of failure for ordinary Internet access.

Direct traffic and proxy traffic are separated before the v2rayA backend.

~~~text
client
  |
  v
vpn-front
  |
  +-- direct class -> freedom outbound -> WAN
  |
  +-- proxy class -> vpn-policy -> 127.0.0.1:20173 -> v2rayA -> VPN
~~~

## Front router

*vpn-front* is a stable Xray process. It owns the LAN TPROXY entry point and is not restarted during node failover.

The front router classifies configured domains and IP ranges. Everything else uses a marked direct socket and bypasses the VPN backend.

## Policy layer

*vpn-policy* determines what proxy-class traffic does when the backend is unavailable.
The public modes are:

- *VPN-only*: proxy traffic remains bound to the VPN backend and cannot fall back to direct.
- *Fail-open*: proxy traffic may temporarily use direct Internet when the VPN backend is unavailable.
- *Direct*: explicit operator override; proxy classification remains active but policy sends it direct.

An internal emergency blackhole configuration is retained for invariant violations. It is not an ordinary response to a slow or degraded VPN.

## Watchdog

The watchdog checks independent connectivity endpoints through the backend SOCKS listener.

Current health states:

- *healthy*: at least 3 of 4 probes succeed.
- *degraded*: 2 of 4 probes succeed; the node remains usable.
- *down*: at most 1 of 4 probes succeeds.

A down result is confirmed before failover. The watchdog stores per-node success/failure counters, consecutive failures, cooldown and EWMA latency.

## Failover

Candidates can come from multiple v2rayA subscriptions.

Supported candidate transports currently include VLESS TCP + Reality, VLESS XHTTP + Reality, VLESS WebSocket + TLS, Hysteria2 and Shadowsocks.

Selection combines a transport base priority with historical health and latency.
## Self-test

The self-test verifies routing invariants without turning the working Mac into a transparent-routing test client.

It checks:

- nftables front table.
- policy rule and route table.
- absence of a global LAN blackhole.
- required services and router management access.
- healthy direct and VPN egress.
- fail-open behavior with a dead backend.
- VPN-only fail-closed behavior with a dead backend.
- emergency blackhole behavior.

## Declarative recovery

The stack manager renders production Xray, nftables and init configuration from manifests.

Apply and restore use a backup-first workflow:

~~~text
backup
  -> render
  -> validate
  -> atomic install
  -> restart
  -> self-test
  -> rollback on failure
~~~
