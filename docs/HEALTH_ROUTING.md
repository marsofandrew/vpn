# Health-aware foreign routing

The `pr-2-transports-v4` tag preserves static v4 routes. This milestone adds
optional `health_settings`, `health`, bounded `route_events`, `node.foreign_only`,
and priority/balanced policies to the same schema. Existing direct and explicit
upstream policies keep their semantics. No probe runs just by importing code.

`upstream` uses one configured path. `priority` keeps the first healthy path in
an ordered list and observes a cooldown before returning to a recovered preferred
path. `balanced` selects the healthy path with the lowest measured first-byte
latency; it is latency selection, not per-connection load distribution. Neither
uses leastPing to approximate strict priority. Explicit direct and block remain
separate policy types.

Each probe starts a private temporary Xray instance with one upstream and a
loopback-only SOCKS listener on the gateway. The HTTPS probe verifies TLS, a 2xx
response, at least 128 KiB transferred (optionally 1 MiB), time to first byte,
transfer duration and throughput. A separate verified HTTPS JSON response
`{"ip":"FOREIGN_EXIT_IP"}` through the same listener must match a configured
exit IP. This checks establishment and authentication through that transport.
Target DNS goes through SOCKS. No default third-party probe URLs are embedded;
operators must choose trusted, stable endpoints and expected egress addresses.
Setup failures never expose credentials or full command output.

Three consecutive successes/failures are the starting thresholds, configurable
per path. Probes default to a 30-second minimum interval. The installed optional
timer waits 30 seconds after a complete cycle, so actual cadence includes probe
duration and state-lock contention. Probes are sequential and share the CLI lock
with quota/manual operations; this favors coherent route/state updates over
parallelism. Bound timeouts should be kept short for the configured node count.

## Operator setup

Run these later on the RU gateway after local tests and backups, not on the
development computer to infer Russian reachability. Replace every placeholder:

```sh
python3 vpnctl.py health configure ny-reality \
  --download-url https://PROBE_HOST/sample.bin \
  --egress-url https://IP_CHECK_HOST/json \
  --expected-exit-ip NY_PUBLIC_IP
python3 vpnctl.py health configure ny-cdn \
  --download-url https://PROBE_HOST/sample.bin \
  --egress-url https://IP_CHECK_HOST/json \
  --expected-exit-ip NY_PUBLIC_IP
python3 vpnctl.py health check
python3 vpnctl.py health
# Wait for successful thresholds before assigning a health-dependent policy.
python3 vpnctl.py policy set foreign --type priority \
  --upstream ny-reality --upstream ny-cdn --cooldown 60 --no-restart
python3 vpnctl.py route set default --policy foreign --no-restart
python3 vpnctl.py node --id ru-vps --role gateway --foreign-only --no-restart
python3 vpnctl.py restart
sudo systemctl enable --now vpnctl-health.timer
python3 vpnctl.py health events
```

The installer creates health units under the same operator account as quota
enforcement but enables them only with `ENABLE_HEALTH_TIMER=1` or the explicit
systemctl command. Enable only after configuring probes. No install command was
run on production during development.

## Fail-closed guarantees and limits

Foreign-only mode rejects assigned direct policies and emits no freedom
outbound. The default outbound is blackhole. All profile traffic follows its
explicit rule without IP, address-family, protocol or DNS exceptions. With no
healthy candidate it selects block, never local egress. Unknown/disabled selected
members also block. No local DNS outbound is added: client DNS traffic arriving
through the VPN follows that profile's rule, while upstream hostname bootstrap
still uses the host resolver. This cannot prevent an end-client OS from sending
DNS or other traffic outside its VPN; configure and test client-side full-tunnel
and DNS rules. It is not a host firewall kill switch for unrelated processes.

Each route change uses the validated PR 1 deployment/rollback transaction.
Consequently this first implementation recreates Xray and disconnects existing
sessions. Clients must reconnect; transparent TCP migration is not promised.
Failed native validation leaves the old route running; failed health validation
attempts rollback, with the same documented rollback-failure recovery procedure.

Changing upstream credentials invalidates its health record. Stored health does
not autonomously expire while the monitor is stopped; running routes stay pinned
to the last selected foreign path and may stall, but do not become freedom.
Enable and monitor the timer. Use `health` for last probe/success, consecutive
failures, error codes, latency, transfer size/duration and throughput, and
`health events` for route changes. Events contain stable names and timestamps.

Tests simulate primary loss, CDN loss, both unavailable, recovery thresholds,
cooldown and selection. Probe tests cover SOCKS authentication, TLS/HTTP errors,
short/trickling downloads, egress mismatch and bounded reads. Docker checks start
a generated foreign-only blocked configuration and validate local service health.
Real NY/CDN reachability and RU network behavior remain unverified. Whitelist-only
mobile access can block every path, including working server-side probes.

## Rollback

Before downgrade, back up state/config and stop the health timer. Assign existing
profiles to explicit single-upstream policies (or block) and remove priority/
balanced definitions before loading the `pr-2-transports-v4` version; it rejects
unknown policy types. Preserve accounting, keys and identities. Never turn a
foreign-only gateway into direct mode as an automatic rollback strategy.
