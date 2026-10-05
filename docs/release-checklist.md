# Release checklist

This checklist is for validating a vpn-guardian package build before tagging a release.

## Reference target

~~~text
OpenWrt 24.10.4
target: mediatek/filogic
architecture: aarch64_cortex-a53
device: GL.iNet GL-MT6000
~~~

## Build

1. Re-enable the OpenWrt package workflow that is intentionally disabled during active development.
2. Run go test ./....
3. Run go vet ./....
4. Run the CGO-disabled cross-build matrix.
5. Build the IPK with the matching official OpenWrt SDK.
6. Verify the packaged vpn-guardian ELF is statically linked.
7. Verify readelf reports no NEEDED dynamic libraries.
8. Inspect the IPK file list: one vpn-guardian binary, required init/hotplug files, config examples and optional nginx config only.

## Safe install preconditions

1. Keep the management computer on an independent upstream network.
2. Verify SSH access to the router through a management path that does not depend on vpn-front.
3. Verify direct Internet access before installation.
4. Create a fresh router backup.
5. Run the exact package binary with vpn-guardian bootstrap --dry-run.

## First install

1. Install the IPK with opkg.
2. Confirm vpn-guardian-api starts.
3. Confirm the dashboard opens directly on LAN port 20175.
4. If nginx is present, confirm vpn.home.arpa proxies to the same dashboard.
5. Confirm v2rayA transparent mode is close.
6. If no VPN node is configured, confirm bootstrap stays pending and ordinary direct traffic is unaffected.
7. Add/import a VPN subscription.
8. Confirm bootstrap completes automatically.
9. Confirm /etc/vpn-guardian/bootstrap-complete exists.

## Runtime validation

1. vpn-guardian status reports all stack components healthy.
2. vpn-guardian selftest passes.
3. Direct traffic uses the home egress.
4. Proxy-class traffic uses the VPN egress.
5. Dashboard reports the same auto-selection candidate count as the watchdog.
6. Stop/freeze the VPN backend and verify direct traffic remains available.
7. Verify VPN-only mode fails closed only for the proxy class.
8. Verify fail-open mode falls back only for the proxy class.
9. Verify watchdog recovery does not restart vpn-front.

## Persistence

1. Reboot the router.
2. Confirm management access before testing VPN traffic.
3. Confirm direct traffic.
4. Confirm vpn-guardian-api, vpn-front, vpn-policy, watchdog and collector start automatically.
5. Confirm v2rayA is still backend-only.
6. Re-run self-test.
7. Confirm dashboard history resumes.

## Upgrade

1. Install a newer IPK over the existing package.
2. Confirm bootstrap re-runs safely.
3. Confirm existing manifests/control state remain intact.
4. Confirm direct traffic remains available throughout.
5. Confirm self-test passes after the upgrade.

## Rollback and removal

1. Force a staged apply failure and verify automatic rollback restores the previous runtime.
2. Test a failure on a clean first install and verify TPROXY state is removed.
3. Remove the package.
4. Confirm generated vpn-guardian routing rules and services are stopped.
5. Confirm ordinary OpenWrt routing still works.
