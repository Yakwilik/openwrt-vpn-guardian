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
