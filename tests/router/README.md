# Router acceptance tests

These tests briefly stop the VPN core and front. Run only on an authorized test router with a separate management path. They do not enable fail-open or change the management firewall.

Build the helper with the same Go toolchain as the application. It is not part of the installed package.

~~~sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o corectl ./tests/router/corectl
~~~

Place the helper at */tmp/vg-corectl* and the script at */tmp/vg-acceptance.sh*. On the router, choose an unused address in its LAN and run:

~~~sh
TEST_ADDRESS=192.168.8.250/24 sh /tmp/vg-acceptance.sh
~~~

The script removes its test network namespace and virtual Ethernet pair. If interrupted during fault injection, it attempts to restart only the affected services. Do not run two copies concurrently.

An existing dashboard PIN is respected: the unauthenticated setup test is skipped rather than bypassing authentication. Management responses and cookies are kept in a private temporary directory and removed at exit. A selected, working VPN node and VPN-only policy are preconditions.

## DNS-first regression tests

Cross-compile the isolated DNS test binaries on a development machine:

~~~sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o /tmp/dnsfront.test ./internal/dnsfront
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o /tmp/dnsproxy.test ./internal/dnsproxy
~~~

Run the binaries explicitly on an authorized OpenWrt test host. The native frontend test starts a separate DNS-only dnsmasq on an ephemeral loopback port and checks that local answers survive a stopped mock upstream. It does not restart the production dnsmasq instance. The proxy matrix covers System/Custom/Xray routing, VPN-only/Fail-open/Direct/blocked behavior, negative answers, policy tightening while a query is in flight, and independent fallback time budgets. Mock DNS/SOCKS servers keep failure-policy tests separate from the production VPN.

After a migration, additionally check the actual LAN path through a temporary network namespace: local A/AAAA/TXT and negative responses, external UDP/TCP DNS, direct/VPN HTTPS separation, local resolution with the Guardian DNS daemon stopped, independent router bootstrap, unchanged DNS process IDs on admin hot reload, and both retained DNAT bypass rules. Do not infer successful bootstrap solely from an open TCP listener.
