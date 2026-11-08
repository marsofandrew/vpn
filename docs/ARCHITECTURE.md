# Architecture and reliability milestone

## Baseline (2026-11-08)

Checkout: marsofandrew/vpn, originally f0839fa. The reviewed pre-existing
server-host validation change is committed separately. All 28 unittest tests
passed before reliability changes. Coverage included rendering, links, import,
legacy migration, profiles, quotas and rollover; deployment, persistence and
concurrency had no failure tests.

## State schema v3

`data/vpn_state.json` is the source of truth. Top-level fields are `version`,
`created_at`, `updated_at`, `usage_period` (UTC YYYY-MM), `server_host`,
`default_domain`, `fingerprint`, `flow`, `spider_x`, nullable `upstream`, and
`profiles`. The upstream holds host/port, UUID, network/security, public key,
server name, short ID, fingerprint, flow and spider path. Each profile has name,
timestamps, port, REALITY target, outbound mode, short ID, private/public keys
and clients. Clients hold name, UUID, email (statistics identity), enabled flag,
quota, uplink/downlink totals, timestamps and disabled reason.

Dependencies: Python cryptography and qrcode; Docker Compose; Xray StatsService
on localhost:10085; host networking; persisted state and generated config.
v1/v2 import preserves identities and defaults old profiles to direct routing.

## Write and runtime paths

`save_state` and `render_and_save_config` are the persistence primitives.
`persist_state_and_config` is used by profile add/remove/outbound, upstream
set/clear, client add/remove/enable/disable, quota set/reset/enforce and render.
Profile/client list and link also persist when the calendar period changes.
`init` and `import-config` write initial state/config directly. Usage refresh
persists observations. The systemd quota timer calls the same CLI every five
minutes. All these commands must share the same state lock.

Previously restart_xray used compose up, and explicit up/down/restart were raw
Compose calls. A file bind mount could retain an old inode after atomic replace;
configuration installation therefore requires container recreation. Quota reads
previously reset counters before committing state and lost data on a crash.

## PR 1 design (before schema changes)

Keep version 3 and all keys, UUIDs, ports and routes. Add optional accounting
metadata only: container ID plus StartedAt identifies a counter epoch; cumulative
per-email checkpoints commit with usage totals. Read counters without reset,
verify the epoch before and after reading, and charge only the difference.
Counter decreases within an epoch are treated as counter resets. Disabled clients
retain checkpoints. Rollover keeps checkpoints and charges only subsequently
observed deltas; traffic spanning a month boundary cannot be split exactly.

Use same-directory temporary files, 0600, fsync, atomic replace and directory
fsync. Keep a validated state backup. Recover missing/corrupt primary state from
that backup, failing closed when neither is valid. POSIX flock surrounds complete
CLI transactions, including reads that can roll over; logs/status need no lock.

Deployment validates generated tags/references and native Xray syntax before
installation. Keep the previous config, atomically install, force recreate, then
check container stability, API and TCP listeners inside its network namespace.
Restore and recreate the previous config on failure. Persist a deployment journal
before installing so a later CLI command can reconcile interrupted deployments.
State-only changes compare the effective config and skip recreation.

## Future migration

v4 is deferred. Back up validated v3 state first, translate the single upstream
to a stable named upstream, translate per-profile routes explicitly, and preserve
every identity, key, counter, port and quota. Reject unsupported transports/routes.
Node inventory will remain separate from runtime state. No rotation scripts or
reference-repository dependencies are introduced in PR 1.

## Compatibility and limits

POSIX locking targets Linux and local macOS development; all operators must use
the same canonical state path and filesystem with flock/atomic rename support.
Old scripts that edit JSON directly do not participate in locking. No local
probe proves Russian client reachability or a REALITY handshake through filtering.
Unexpected Xray termination can lose traffic since the last poll. Accounting is
not exactly once across Xray crashes; controlled recreation samples first but
has a small sampling-to-stop gap. Downgrading to the old resetting poller is not
safe without explicitly resetting accounting checkpoints and establishing a new
counter epoch. Production deployment and network validation remain operator work.
