# Release checklist

Validate each package build on its declared OpenWrt target before publishing a release. Record the firmware, target and device used for every router test.

## Package builds

The enabled [OpenWrt package workflow](../.github/workflows/package.yml) builds this matrix:

| OpenWrt | Target | Package architecture |
|---|---|---|
| 24.10.4 | mediatek/filogic | aarch64_cortex-a53 |
| 24.10.4 | ipq40xx/generic | arm_cortex-a7_neon-vfpv4 |
| 24.10.4 | x86/64 | x86_64 |

The GL-MT6000 is one runtime reference device. Packages are selected by firmware and architecture, not by that model name.

1. Pass *go test ./...*, *go vet ./...* and *go test -race ./...*.
2. Build each IPK from the intended immutable source commit using the matching official SDK.
3. Confirm the SDK checksum and pinned feed revisions are recorded by the build.
4. Verify the packaged executable is the target architecture, uses *CGO_ENABLED=0* and has no dynamic ELF dependencies.
5. Check the package dependency list against the matching firmware feeds.
6. Inspect package contents: one binary, static init/hotplug files, validated configuration examples and the optional nginx virtual host.
7. Confirm ordinary branch builds upload artifacts and release tags publish packages only after tests and all package builds succeed.

## Router preconditions

1. Keep a working management connection independent from vpn-front.
2. Verify ordinary Internet access before installation.
3. Create a router backup and record the current firmware/package architecture.
4. Use packages and dependency feeds matching that firmware.

## First installation and setup gates

1. Install the IPK with *opkg*. Confirm installation prints the *vpn-guardian init* command and does not start Guardian interception.
2. Run *vpn-guardian init* from an interactive root terminal.
3. Confirm the detected LAN/WAN values match the router; test manual input when detection is unavailable.
4. Choose allowed transports and enter subscription URLs if requested. Confirm private URLs are omitted from summaries and errors.
5. Confirm dependencies and generated configuration pass validation before backend preparation and routing activation.
6. Confirm v2rayA runs with *transparent=close*, its local API is accessible and a working allowed node is selected.
7. Confirm setup completes, records */etc/vpn-guardian/bootstrap-complete* and enables runtime services.
8. Open the dashboard directly on the LAN address at port 20175. If nginx is available, check the optional *vpn.home.arpa* proxy separately.

Exercise the failure gates on an isolated router:

- Cancel the wizard before confirmation: no Guardian configuration or services are activated.
- Remove or make a dependency inaccessible: setup reports the dependency and stops.
- Supply incomplete manifests or an invalid transport allowlist: setup cannot start the stack.
- Remove one file from an existing manifest pair: bootstrap must not replace established routing with defaults.
- Import a subscription with no allowed nodes, or make every allowed backend unusable: setup stops before first-time interception.
- Run *bootstrap --non-interactive* with missing input: it returns an error without waiting for stdin or starting a retry loop.
- Run *bootstrap --dry-run* with a complete configuration: it reports checks without modifying configuration, subscriptions, services or routing.

## Runtime validation

1. *vpn-guardian status* reports the stack components running.
2. *vpn-guardian selftest* passes.
3. Direct traffic uses the home egress; proxy-class traffic uses the VPN egress.
4. Dashboard, control and watchdog report the same eligible candidates for the configured allowlist.
5. Verify manual and automatic selection cannot use forbidden transports.
6. Stop or freeze the VPN backend and verify direct traffic remains available.
7. Verify VPN-only blocks the proxy class during backend failure and fail-open follows its explicit policy.
8. Verify backend recovery does not restart vpn-front.
9. Stop vpn-front in VPN-only mode: interception remains active until watchdog recovery. Do not connect a TCP probe to its TPROXY listener.

## Persistence

1. Reboot the router and confirm independent management access.
2. Confirm the API, front, policy, watchdog and collector start automatically.
3. Confirm v2rayA remains backend-only and the configured transport allowlist is retained.
4. Verify direct/VPN separation, rerun the self-test and check that dashboard history resumes.

## Upgrade

1. Install the next IPK over a configured installation.
2. Confirm existing manifests, routing rules, subscriptions and management state remain intact.
3. Run *vpn-guardian bootstrap --non-interactive* to validate and activate the updated runtime.
4. Confirm the allowlist is preserved and direct/VPN separation and self-test pass.
5. Confirm an incomplete configuration requires an explicit *vpn-guardian init* instead of an inferred migration.

## Rollback and removal

1. Force a staged apply failure and verify rollback restores the previous generated runtime and manifest pair.
2. Fail reconfiguration after a new backend has been selected; verify the previous permitted connection is restored.
3. Test a failed clean first install and verify generated interception is removed.
4. Remove the package and confirm its generated routing rules and services stop.
5. Confirm ordinary OpenWrt routing works after removal.
