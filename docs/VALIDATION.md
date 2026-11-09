# Local validation and milestone tags

No production hosts, keys, clients, certificates, routes or deployments were
modified. All tags and branches are local; no PR or push was created.

## Review checkpoints

| Tag | Scope |
| --- | --- |
| `pr-1-reliability` | Initial transactional deployment, persistence and accounting |
| `pr-1-reliability-reviewed` | Timer ownership and rollover/recovery regression fixes |
| `pr-2-transports-v4` | Preserving migration, named upstreams, XHTTP and route assignments |
| `pr-3-health-routing` | Gateway probes, hysteresis, priority selection and fail-closed routing |
| `pr-4-client-fallbacks` | Independent entries, private subscriptions and optional ECH |
| `pr-5-node-inventory` | Separate inventory and stable exit-node references |

These are implementation review checkpoints, not production release approvals.
Earlier tags carry older Xray pins; use the final official-image update when
reviewing deployment readiness. Each guide documents compatibility, rollback
and limits for its milestone.

## Current official runtime

Compose and integration-test defaults use only
`ghcr.io/xtls/xray-core:26.10.31`. The version is also the explicit ECH capability
pin. Older overridden images cannot silently accept ECH fields during deployment:
native output must identify the tested version. No alternate image is selected
automatically. The removed legacy native `echForceQuery` field is not emitted;
the state contract still rejects weaker ECH query policy values.

The official release source and security notes are at
[Xray 26.10.31](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31).
An image upgrade does not update or secure the host kernel; follow upstream
host patch guidance during the later operator rollout.

## Evidence and outstanding checks (2026-11-09)

- Baseline: 28 existing unit tests passed before PR 1.
- Current standard suite: 215 tests discovered, 200 passed and 15 opt-in
  integration checks skipped without integration flags.
- Official 26.10.31 macOS ARM64 release binary: its ZIP matched the published
  SHA256 `0a05dca3bd311b0bc5a89c7ce56350cab1e829e131e4b2bcd48eb304fac07e9a`.
  All 35 transport tests passed with `XRAY_BINARY`, including native generated
  configuration checks. This verifies the binary, not the container image.
- Ruff lint and new-module formatting checks, targeted mypy checks, Python
  compilation, shell syntax, workflow YAML parsing and Compose parsing passed.
- Python runtime dependency audit: no known vulnerabilities reported by
  pip-audit against requirements.txt at the time of the check.
- Before the official-image-only update, the complete 215-test suite passed
  using an alternate image containing Xray 26.3.27. This included transactional
  recreation/rollback, a blocked foreign-only runtime, verified TLS/ECH transfers
  of 128 KiB, plain-TLS fallback, and negative ECH cases. That older image later
  failed the high/critical vulnerability scan; it is not the current pin or a
  supported deployment recommendation.
- Official GHCR pulls returned HTTP 403 for both normal and isolated anonymous
  Docker configurations. Therefore **official 26.10.31 container runtime tests,
  ECH container regressions and its image vulnerability scan remain pending**.
  They are not claimed as passed based on another publisher's image.
- Real CDN deployment, ECH DNS discovery, foreign egress and fixed/mobile
  accessibility in Saint Petersburg, Moscow and Berezniki remain untested.
  Server-side success does not establish Russian client accessibility.

## Repeatable checks

```sh
python3 -m pip install -r requirements-dev.txt
ruff check --select F,E9 .
ruff format --check vpn_*.py
mypy --ignore-missing-imports vpn_transports.py vpn_health.py vpn_monitor.py vpn_subscriptions.py vpn_inventory.py
python3 -m unittest discover -s tests -v
docker compose config -q
docker pull ghcr.io/xtls/xray-core:26.10.31
XRAY_INTEGRATION=1 XRAY_TRANSPORT_INTEGRATION=1 python3 -m unittest discover -s tests -v
pip-audit -r requirements.txt
docker run --rm aquasec/trivy:0.61.1 image --scanners vuln --severity HIGH,CRITICAL --exit-code 1 ghcr.io/xtls/xray-core:26.10.31
```

Integration tests create temporary local fixtures and containers; port 10085
must be free. Formatting/type checks cover the new modules; legacy CLI style is
preserved. CI runs unit/migration/native/runtime checks, Compose validation and
dependency/image audits. Security findings fail the gate; none are suppressed.
CI was added locally and has not been run on GitHub because nothing was pushed.
Do not deploy until the official-image gate and the documented staged network
checks pass. No full multi-node orchestration or CGNAT tunnel is implemented.
