# Migration plan

The repository is being extracted from a working router. Production must remain recoverable throughout the migration.

## Phase 1 — unified binary

Implemented:

- watchdog logic behind vpn-guardian watchdog.
- stack manager behind vpn-guardian stack and top-level stack commands.
- self-test behind vpn-guardian selftest.
- v2rayA control compatibility behind vpn-guardian control.
- dashboard collector behind vpn-guardian collector.
- status, history and control CGI APIs behind vpn-guardian api.
- legacy executable/CGI names resolved through symlinks to one binary.

## Phase 2 — first-run bootstrap

Implemented:

- automatic LAN/WAN interface discovery.
- automatic LAN CIDR/address discovery.
- manifest creation on first install.
- generated Xray front/policy configuration.
- generated nftables and policy-routing configuration.
- automatic v2rayA backend-only mode.
- automatic dashboard DNS and nginx/fcgiwrap setup.
- backend-aware activation: front is not enabled until the v2rayA SOCKS backend is ready.
- bootstrap --dry-run preflight.
- automatic retry through vpn-guardian-bootstrap.
- runtime rollback in addition to file rollback.

## Phase 3 — OpenWrt package

Implemented in the package recipe:

- one executable at /usr/bin/vpn-guardian.
- compatibility command symlinks.
- status/history/control CGI symlinks.
- vpn-front and vpn-policy init scripts.
- first-run bootstrap init service.
- dashboard assets and nginx configuration.
- generic config examples outside /etc.
- pre-install preservation of the legacy control CGI for PIN/session migration.
- post-install automatic bootstrap.

Package validation target:

~~~text
OpenWrt 24.10.4
mediatek/filogic
aarch64_cortex-a53
GL.iNet GL-MT6000
~~~

The GitHub Actions package workflow builds against the matching official OpenWrt SDK.

## Phase 4 — controlled production cutover

Before installing the package on the reference router:

1. Keep the management computer on an independent upstream network.
2. Verify management access to the router through its WAN-side management address.
3. Create a fresh vpn-stack backup.
4. Build the package from the exact commit to be installed.
5. Run vpn-guardian bootstrap --dry-run using the temporary binary.
6. Validate collector, status/history/control APIs and candidate count from /tmp.
7. Install the IPK.
8. Wait for bootstrap-complete.
9. Verify direct egress first.
10. Verify proxy-class egress separately.
11. Run the complete self-test.
12. Verify dashboard, control API and reboot persistence.
13. Roll back immediately on any invariant failure.

## Phase 5 — cleanup after cutover

After the package has survived the controlled install and reboot tests:

- remove obsolete standalone binaries.
- remove obsolete dashboard collector/CGI source copies.
- move duplicated v2rayA SQLite parsing and API code into a shared internal package.
- add focused unit tests for candidate eligibility, policy selection, history/event normalization and bootstrap discovery.
- tag the first package release.
