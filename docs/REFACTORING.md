# SRP refactor

This is a behavior-preserving extraction of the schema v4 implementation.
`vpnctl.py` remains the executable and exports `main` and `VpnctlError`.
Internal helper imports and monkeypatch locations are intentionally changed.
Existing CLI arguments, output, links, native configuration, identities,
metadata, accounting checkpoints, and deployment ordering remain contracts.

## Boundaries

`vpn_manager/state` separates creation, import, migration, validation and storage.
`files.py` owns private atomic publication; state storage adds backup/recovery
policy, while subscription exports do not create backups.
`vpn_manager/xray` separates native rendering, Compose adapters and deployment
transactions. `DeploymentService` receives storage, runtime control and a usage
sampler. `UsageService` receives statistics and a calendar. The narrow protocols
in `ports.py` describe only operations consumed by those workflows.

`vpn_manager/transports` separates shared field checks, canonical validation,
URI import/export and native rendering. Explicit transport/security handler maps
keep dispatch separate from each handler. `vpn_manager/health` separates pure
policies, deadline-aware wire I/O, HTTP framing, measurements and probe resources.
`ProbeSession` alone owns its temporary file and named container; cleanup failures
remain observable. Root `vpn_*` modules explicitly re-export their public APIs.
Inventory and structural validation remain stdlib-only and import without CLI or
runtime initialization.

`vpn_manager/cli/composition.py` assembles adapters and binds each CLI handler
to its required dependencies. The parser only registers arguments and command
handlers. Health configuration and decision orchestration live in
`health/service.py`; the CLI formats observations/events and persists results.
Read-only Compose handlers receive only a Compose runner. Domain code does not
receive `argparse.Namespace`.

The full command lock still surrounds recovery and command execution. Native
preflight precedes installation; accounting checkpoints precede journal creation.
Rollback retains the original journal on failure. Recreation still interrupts
connections. No seamless connection migration is introduced.

## Compatibility and rollback

No state migration or installation operation is needed for this refactor. Install
the complete checkout, including `vpn_manager`; copying only `vpnctl.py` is no
longer sufficient. Standalone public `vpn_*` APIs remain available. To roll back,
restore the previous complete checkout; the on-disk schema remains version 4.
Never restore old usage state merely to roll back Python code.

Synthetic fixtures capture CLI help/options/defaults and representative state,
configuration and links. They contain no deployment credentials. Existing tests
continue to cover locking, atomic writes, rollback, quotas and fail-closed routes.
Official-image Linux integration remains a separate gate; unit tests cannot
establish runtime equivalence or Russian client accessibility.

## Local function-size policy

Run `python3 scripts/check_function_size.py` after formatting. It scans all
tracked and unignored Python files reported by Git, including tests, fixtures,
utility scripts, nested functions, async methods and lambdas. It counts physical
lines from `def`/`lambda` through the last statement, including signatures,
docstrings and blank lines. Decorators are outside that span.

The maximum is 60 with no exemptions. The preferred maximum is 30. Every current
31–60-line function has a cohesion-based explanation in
`function_size_justifications.json`; missing and stale explanations fail the
guard. These explanations never waive the 60-line limit. The unit suite runs
the same check. New code should target 30, without packed statements or helpers
that merely conceal unrelated responsibilities. No CI is configured.
