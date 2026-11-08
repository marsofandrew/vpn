# Reliability operations and review notes

## Behavior changes

State remains v3. Existing client UUIDs, keys, short IDs, ports, routing and
quotas are retained. Optional `accounting` contains `epoch` (container ID,
StartedAt, running status) and cumulative `checkpoints` by client email and
uplink/downlink direction. Totals and checkpoints are committed together.
Never run an old resetting poller alongside this version.

Every CLI state transaction takes a POSIX file lock at `vpn_state.json.lock`.
The timer and manual commands must use the same absolute state path, same
operator permissions, and same config/Compose paths. Status and streaming logs
do not block mutations. Direct JSON edits and other independent Xray managers
are outside this locking contract.

Files are atomically replaced with mode 0600 and fsync. A validated previous
state is kept at `.bak`; missing or corrupt primary state recovers from it.
The backup can be one update behind, so recovery is reported on stderr.
Temporary files left by SIGKILL are ignored, never used as authoritative state.
Use an access-controlled filesystem; the Docker socket remains root-equivalent.

Changed runtime configurations undergo tag/reference checks and native Xray
validation using a **separate candidate mount**. A journal records the previous
state/config before installation. Force recreation ensures file bind mounts see
the new inode. API availability, TCP listeners and a stable container epoch are
checked; failure restores the previous config and recreates it. An interrupted
transaction is rolled back before the next CLI command, using the same paths.
If rollback itself fails, the journal remains and the command reports failure.
Do not delete that journal to bypass recovery.

`render` and `--no-restart` stage `config.json.pending` and save desired state;
they do not replace a live configuration. `restart` or `up` validates and applies
the desired state. Init/import create the initial config when absent, otherwise
stage it. State-only changes skip recreation when effective config is unchanged.
Explicit restart always recreates. Recreation interrupts established connections.

The image is pinned to Xray 25.3.6 for compatibility validation; a version pin is
not a security audit. `XRAY_IMAGE` overrides require their own validation. Root
is retained to read mode-0600 host secrets and bind existing low ports without
changing ownership on deployed hosts. All capabilities are dropped except
NET_BIND_SERVICE; root filesystem is read-only and new privileges are disabled.
Host networking remains required on Linux. The API listens only on 127.0.0.1.
Access logging is disabled; warning/error output goes to Docker's logs. Explicit
link/init/client-add commands intentionally print connection credentials; do not
send their output to shared logs. QR files are mode 0600. No certificates or
subscription service are introduced.

## Accounting guarantees and limitations

Polling never resets Xray counters. A failed poll/commit can be retried without
losing already observed bytes or charging the same snapshot twice. Container
ID plus StartedAt distinguishes restarts even when new counters exceed old ones.
An epoch change during a read rejects that read. Counter decreases handle manual
counter resets, but a reset that grows past the last checkpoint before polling
cannot be detected; external counter resets are unsupported.

Manual disable/re-enable retains checkpoints. Monthly rollover and quota reset
retain checkpoints too, preventing lifetime counters from being recharged.
Unobserved traffic spanning a calendar boundary is assigned to the first poll's
month; use frequent polling to limit this ambiguity. Controlled recreation polls
and commits usage first. Traffic between that poll and stop, or since the last
poll before an unexpected Xray crash, can be lost. This is not exactly-once
accounting across Xray crashes. A restored older state backup may also replay
or lose observations across epochs. Disabled clients are removed at apply time;
`--no-restart` deliberately postpones enforcement.

## Operator migration and rollback

Development does not run these commands on production. Before a staged rollout,
stop the old quota timer and back up state/config, Compose overrides, keys and
QR files privately. For example, from the production checkout:

```sh
sudo systemctl stop vpnctl-quota.timer
umask 077
tar -czf ../vpn-before-p0.tar.gz data docker-compose.yaml
# Back up .env and qrcodes separately if present; keep backups off shared storage.
python3 -m unittest discover -s tests -v
python3 vpnctl.py restart
python3 vpnctl.py validate
python3 vpnctl.py usage --refresh
sudo systemctl start vpnctl-quota.timer
```

First verify NY existing client handshakes and exit IP, then update RU and verify
RU-to-NY routing. The automatic deployment rollback preserves the prior state
and config. For a code downgrade, stop the timer, snapshot latest non-resetting
usage, stop Xray, keep an additional backup, then restore the pre-upgrade code,
Compose and matching state/config backup together. Start a new Xray process to
establish fresh counters before restarting the old timer. Usage after the backup
requires manual reconciliation. Never use `init --force` as a rollback method.

## Validation

```sh
python3 -m unittest discover -s tests -v
docker compose config -q
XRAY_INTEGRATION=1 python3 -m unittest discover -s tests -p test_xray_integration.py -v
```

The integration test creates an isolated Compose project and temporary secrets,
publishes TCP listeners on localhost, and removes its containers afterward. Port
10085 must be free locally. It checks native rejection without replacing the
running container, force recreation, live statistics reads and injected health
failure rollback. It does not establish a client REALITY session, measure real
traffic/quota cutoff or establish accessibility from Russian networks.

Local evidence: 28 baseline tests passed. The official GHCR image pull returned
403 in this environment; local runtime checks use the same Xray 25.3.6 binary in
`teddysun/xray:25.3.6` (digest
`sha256:3e37257dbd81dd07f5b71c13228f4b3f0feec21349531eb48650cfaf8393de91`)
with an explicit xray entrypoint. This is a test override only; production Compose
continues using the official image. Repeat the integration test against GHCR
before deployment. The reference repository was reviewed for context only; its
rotation/provisioning code is not included.
