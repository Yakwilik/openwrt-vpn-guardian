# Subscription API validation — 2026-10-05

## Scope

The starting commit was *8fd017f37ac16f7b37bdfb0696fcb07a37080a05*. Its subscription name fix was already present in the Mac checkout and on the router.

This update isolates subscription parsing in *internal/control/subscription.go*, accepts only strings for optional text fields, and omits the subscription address from read-only JSON. Display names follow *remarks → host → Subscription #ID*. The embedded dashboard continues to use the server-provided name.

## Build and regression checks

All commands completed successfully on the Mac with Go 1.26.1:

~~~sh
gofmt -w internal/control/control.go internal/control/subscription.go internal/control/subscription_test.go
git diff --check
go test ./...
go vet ./...
go test -race ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o dist/vpn-guardian-linux-arm64 ./cmd/vpn-guardian
~~~

The result was verified as a statically linked ARM64 Linux ELF executable. Its SHA-256 was checked again after transfer and after installation:

~~~text
99101ad36798a0f13cbf7279cdfaabb872ece3f2eb1b8ca78a29de477bc022ed
~~~

The binary was built before committing the changes, as required by the deployment sequence. Its Go build metadata therefore records the starting revision above with *vcs.modified=true*.

The regression tests cover missing and null fields, empty and whitespace-only strings, display-name precedence, node counts, auto-selection, and unexpected numeric, boolean, object and array values. JSON round-trip tests verify actual wire values, including HTML-escaped nil placeholders, and distinguish read-only from authenticated subscription address visibility. Subscription URLs in tests are synthetic.

## Live deployment

Deployment completed at 16:10 UTC / 19:10 Moscow time.

The executable was staged under */usr/bin*, verified against the build checksum, and installed by a rename on the same filesystem. Only *vpn-guardian-api* and *vpn-dashboard-collector* were restarted.

The previous executable remains in */root/vpn-guardian-checkpoint-subscriptions-20261005-161029/vpn-guardian*.

| Service | PID before | PID after |
|---|---:|---:|
| vpn-front | 12352 | 12352 |
| vpn-policy | 12185 | 12185 |
| v2raya | 13351 | 13351 |
| vpn-backend-watchdog | 13397 | 13397 |
| vpn-guardian-api | 7927 | 30225 |
| vpn-dashboard-collector | 13443 | 30277 |

All three Xray process IDs were unchanged. Before/after hashes matched for the stateless nft listing of *inet vpn_front*, policy rules, IPv4 routes, stack and routing manifests, generated front configuration and nft rules, OpenWrt network and firewall configuration, and the separate home-management routing script.

## API and dashboard

Both the router-local standalone API and the MGTS path through *http://vpn.home.arpa* passed the same read-only response assertions.

| Subscription | Name | Remarks | Nodes | Address key |
|---|---|---|---:|---|
| 1 | sub.conn-liberty.net | Empty string | 33 | Absent |
| 2 | your-durev.com | Empty string | 44 | Absent |

The complete decoded control response contained no nil placeholders.

The dashboard retrieved over HTTP matched *internal/api/web/index.html* byte for byte. Its actual *renderSubscriptions* and escaping functions were executed with the live API response in a Node VM with a minimal document target. Both card titles matched the expected names, with no undefined values or escaped nil placeholders. This was an HTTP and JavaScript rendering check, not a full browser interaction test.

The final status reported Auto mode, killswitch policy, active TPROXY, no direct fallback, zero failures, health 4/4, 77 candidates out of 77 nodes, and all six services running.

## Traffic smoke test

Only the baseline portion of *tests/router/acceptance.sh* was executed, ending before the dashboard write and fault-injection sections. It used a temporary LAN client at *192.168.8.250/24* attached to *br-lan*.

The LAN dashboard and router admin responded. The direct egress returned by *https://icanhazip.com* matched the Mac's MGTS egress. The proxy-class request to *https://chatgpt.com/cdn-cgi/trace* returned a different VPN egress. Public egress addresses are deliberately omitted from this report.

The temporary namespace, veth and resolver directory were removed and their absence verified.

The bootstrap, front, routing and backend services were not restarted by this update. No fault injection or reboot was repeated. No active connection was made to the TPROXY listener. The OpenWrt package/IPK workflow remains disabled.
