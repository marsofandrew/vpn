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

## Historical evidence (2026-11-09)

- Baseline: 28 existing unit tests passed before PR 1.
- At that checkpoint: 215 tests discovered, 200 passed and 15 opt-in
  integration checks skipped without integration flags.
- Official 26.10.31 macOS ARM64 release binary: its ZIP matched the published
  SHA256 `0a05dca3bd311b0bc5a89c7ce56350cab1e829e131e4b2bcd48eb304fac07e9a`.
  All 35 transport tests passed with `XRAY_BINARY`, including native generated
  configuration checks. This verifies the binary, not the container image.
- Ruff lint and new-module formatting checks, targeted mypy checks, Python
  compilation, shell syntax and Compose parsing passed.
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

## Stabilization checks (2026-11-10)

- Standard suite: 261 tests discovered, 244 passed and 17 opt-in integration
  checks skipped. The helper tests include an actual loopback fault-proxy test;
  local socket binding must be permitted by the execution environment.
- The official 26.10.31 binary again passed all 35 transport tests. Ruff lint,
  new-module formatting, targeted mypy checks, Python compilation, shell syntax
  and the resolved default Compose configuration-mount check passed.
- Regression coverage now includes malformed state and legacy structures,
  semantic errors without backup fallback, secret-free validation errors,
  subscription artifact/symlink protection, unverified probe observations,
  ECH probe version mismatches and pre-install/recovery mount mismatches.
- Two new Linux integration scenarios exercise actual gateway-to-exit traffic,
  usage polling, restart checkpoints, quota cutoff, routing changes, primary
  failure, both paths unavailable and recovery cooldown. Their fixture helpers
  passed five local checks, but the actual Docker traffic scenarios have not run.
- An explicit request for the new scenarios on this macOS host reported the
  Linux/local-host-network prerequisite as a skip, not a passed acceptance check.
  The official image was not cached, and its pull again returned GHCR HTTP 403.
  Official container runtime, ECH regressions and image scanning remain blocked.
- No alternate image was used. No `stabilization-local-v1` acceptance tag was
  created. Dedicated REALITY authentication and rejected-credential tests remain
  deferred; valid REALITY traffic is only part of the chaining scenario.
- CI has been removed. Development dependencies and manual validation commands
  remain available. No production changes or remote pushes were performed.

The new integration fixture uses a temporary trusted CA and a fixture-only
native `useSystemCA` setting for TLS outbounds. Certificate verification stays
enabled; production rendering and the host trust store are unchanged. It also
retains private file modes, read-only mounts and capability restrictions. Linux
bind-mount ownership/readability remains part of the pending runtime check.

Run the new scenarios on native Linux with a local Docker daemon and port 10085
free. An unavailable official image produces an error without trying another
publisher:

```sh
XRAY_INTEGRATION=1 python3 -m unittest discover -s tests -p test_stabilization_integration.py -v
```

## SRP refactor checks (2026-11-11)

- Pre-refactor baseline: 261 discovered, 244 passed, 17 opt-in integration skips.
- Current suite: 284 discovered, 264 passed, 20 opt-in integration skips. The
  increase in integration skips comes from splitting the combined deployment
  scenario into four independent tests; no previous assertions were discarded.
- Physical-line guard: 855 functions/methods/lambdas, 761 at or below the preferred
  30 lines, 94 between 31 and 60 with recorded cohesion justifications, zero above
  the hard 60-line limit. The unit suite enforces the same guard.
- CLI help/options/defaults, rendered configuration, links, migration metadata
  and safe errors match synthetic behavior snapshots. New tests also cover CLI
  dependency bindings, injected workflow boundaries and public API re-exports.
- Official 26.10.31 release binary: all 35 transport tests passed, including native
  generated configuration checks. This does not verify the Docker image.
- Ruff lint and full-project formatting, mypy checks across 60 production/guard
  sources, compilation, shell syntax and Compose validation passed. The static
  import graph is acyclic across 59 production modules. Type checks cover annotated
  boundaries; this is not a claim that every legacy function is strictly typed.
- Official image pull again failed with GHCR HTTP 403. The ECH integration entry
  point failed before running a test because that image is unavailable. The five
  stabilization helper tests passed; its live class explicitly skipped because
  macOS/Docker Desktop does not support this fixture's native Linux host network.
- Official-image runtime equivalence, Linux traffic/accounting/failover scenarios
  and the existing network-deployment gates remain pending. No alternate image,
  production deployment, remote push or acceptance tag was used.

See [REFACTORING.md](REFACTORING.md) for package boundaries, internal API changes,
rollback guidance and the size policy. Install or restore the complete checkout,
including `vpn_manager`; the schema remains v4 and no data migration is needed.

## Repeatable checks

```sh
python3 -m pip install -r requirements-dev.txt
ruff check --select F,E9 .
ruff format --check .
mypy --ignore-missing-imports vpn_manager vpnctl.py vpn_*.py scripts/check_function_size.py
python3 scripts/check_function_size.py
python3 -m unittest discover -s tests -v
docker compose config -q
docker pull ghcr.io/xtls/xray-core:26.10.31
XRAY_INTEGRATION=1 XRAY_TRANSPORT_INTEGRATION=1 python3 -m unittest discover -s tests -v
pip-audit -r requirements.txt
docker run --rm aquasec/trivy:0.61.1 image --scanners vuln --severity HIGH,CRITICAL --exit-code 1 ghcr.io/xtls/xray-core:26.10.31
```

Integration tests create temporary local fixtures and containers; port 10085
must be free. Formatting checks cover all project Python sources; type checks
cover annotated package, facade and guard boundaries. Validation is manual: no
GitHub Actions workflow is configured.
The commands above run unit/migration/native/runtime checks, Compose validation
and dependency/image audits locally. Security findings are not suppressed.
Do not deploy until the official-image gate and the documented staged network
checks pass. No full multi-node orchestration or CGNAT tunnel is implemented.
