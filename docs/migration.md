# Migration plan

The repository is being extracted from a working router. Production must remain recoverable during migration.

## Phase 1 — unified binary

Completed in the repository baseline:

- watchdog logic moved behind *vpn-guardian watchdog*.
- stack manager moved behind *vpn-guardian stack* and top-level stack commands.
- self-test moved behind *vpn-guardian selftest*.
- v2rayA control compatibility moved behind *vpn-guardian control*.
- legacy executable names can resolve to the same binary through symlinks.

The production router is not switched to the repository build until compatibility tests pass.

## Phase 2 — common packages

Remove duplication between watchdog and control logic:

- v2rayA SQLite access.
- local JWT signing and API client.
- candidate discovery.
- control state.
- node switching.
## Phase 3 — dashboard backend

Replace the remaining standalone status collector and CGI binaries with subcommands of *vpn-guardian*:

~~~text
vpn-guardian collector
vpn-guardian api status
vpn-guardian api history
vpn-guardian api control
~~~

Dashboard files should then be fully reproducible from this repository.

## Phase 4 — OpenWrt package

The package will:

- install one executable at */usr/bin/vpn-guardian*.
- create compatibility symlinks for legacy commands.
- install init scripts.
- install default manifests.
- install dashboard assets and nginx configuration.
- preserve user configuration on upgrade.

## Phase 5 — production cutover

Before replacing the current router installation:

1. Create a full *vpn-stack backup*.
2. Copy the repository build to a temporary path.
3. Run status, health and self-test using the temporary binary.
4. Replace binaries atomically and create symlinks.
5. Restart one component at a time.
6. Run the complete self-test.
7. Roll back immediately on any invariant failure.
