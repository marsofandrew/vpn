"""Standalone health decisions and an opt-in, stdlib-only SOCKS5 HTTPS probe.

Public API (no persistence, scheduling, routing changes, or default probe URLs):

* select_route(policy, upstreams, health, now) -> stable upstream ID or None.
  Policies use ``type`` and an ordered ``upstreams`` list, matching v4 policy
  records. Types: upstream (exactly one member), priority, balanced. Priority
  optionally takes ``current_upstream`` and ``cooldown`` (seconds, default 60).
  A healthy current member is kept until a preferred member's ``restored_at``
  is at least cooldown seconds old. Without a healthy current member, failover
  is immediate. Balanced minimizes ``latency_ms``; absent measurements sort
  last and ties follow member order. Missing, disabled, or nonhealthy members
  are excluded. Direct/block return None for the orchestrator to handle;
  None never authorizes direct fallback. Unknown policy types raise ValueError.
* record_probe(previous, result, now, config) -> new health dictionary.
  Config: ``interval`` (30 seconds), ``fail_threshold`` (3),
  ``success_threshold`` (3). ``cooldown`` (60) is validated here and supplied
  separately to priority policies by the orchestrator. Status starts unknown;
  consecutive results transition it to healthy/unhealthy at the thresholds.
  Success requires both success and exit_ip_verified to be exactly True.
  ``restored_at`` marks each transition to healthy, not each successful probe.
  ``next_probe_at`` is advisory: callers schedule probes and pass ordered
  timestamps; every call records an actual observation, even within interval.
* probe_path(socks_host, socks_port, download_url, egress_url,
  expected_exit_ips, bytes_required=131072, timeout=15) -> result dictionary.
  Both URLs must be operator-configured HTTPS URLs without credentials or
  fragments. Success requires 2xx responses, at least bytes_required body
  bytes, and an egress JSON object {"ip": "literal IPv4 or IPv6 address"}
  matching a nonempty expected_exit_ips sequence. Missing verification config
  fails before any connection. There is no unverified healthy mode.

Probe results contain success, error (a fixed code or None), status_code,
egress_status_code, latency_ms (time to first download HTTP octet, including
SOCKS/TLS setup), body_bytes, download_time_ms, total_time_ms, throughput_bps
(body bits / complete download sample time), and exit_ip_verified. Failed
probes may contain partial measurements. record_probe copies these metrics
and adds status, consecutive_failures, consecutive_successes, last_probe,
next_probe_at, last_success, restored_at. Inputs are never mutated.

Limits: unauthenticated SOCKS5 on numeric loopback (localhost means 127.0.0.1);
target DNS is performed by SOCKS, never locally. TLS uses system trust and
hostname verification. No redirects, retries, decompression, or proxy env vars.
Download samples are 128 KiB..16 MiB and stop at the requested size, without
reading the rest of a larger response. Egress JSON is at most 16 KiB. Header
reads and additional wire/framing bytes each have a 64 KiB budget. One
monotonic deadline covers both requests, including each underlying read, so
trickling headers/chunks cannot reset it. OS scheduling and certificate-store
loading cannot be preempted. Separate connections use the same SOCKS listener;
the operator must dedicate that listener to one upstream (this module cannot
prove listener routing or end-client reachability). No endpoint data, URLs,
credentials, exception text, or observed exit addresses enter error messages.

Protocol references: https://www.rfc-editor.org/rfc/rfc1928 and
https://docs.python.org/3/library/ssl.html#ssl.create_default_context"""

from vpn_manager.health.measurement import probe_path as probe_path
from vpn_manager.health.policies import record_probe as record_probe
from vpn_manager.health.policies import select_route as select_route

__all__ = ["select_route", "record_probe", "probe_path"]
