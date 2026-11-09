# Infrastructure inventory (PR5 preparation)

`vpn_inventory.py` describes infrastructure independently of runtime VPN state.
It uses only the Python standard library, imports no `vpnctl` code, and performs
no file writes, DNS lookups, network access, provisioning, or runtime changes.
The CLI offers explicit inventory creation/validation; it never loads inventory
automatically during Xray rendering or deployment.

This stage establishes **no tunnels**. In particular, an outbound home node
behind CGNAT is permitted as planning metadata. It does not become reachable,
an active exit, or connected to a gateway. Reverse connectivity, relays, tunnel
setup, routing, and reachability checks belong to a future stage.

## Separate JSON contract

Keep inventory in a separate JSON document, for example `inventory.json`, rather
than in `data/vpn_state.json` or a rendered Xray config. The module does not
create this file. Version 1 has this shape:

```json
{
  "version": 1,
  "nodes": [
    {
      "id": "ru-vps",
      "role": "gateway",
      "country": "RU",
      "connectivity": {"mode": "public", "host": "ru-vps.example.com"},
      "transports": ["vless-reality"]
    },
    {
      "id": "ru-home",
      "role": "gateway",
      "country": "RU",
      "connectivity": {"mode": "outbound"},
      "transports": []
    },
    {
      "id": "ny-vps",
      "role": "both",
      "country": "US",
      "connectivity": {"mode": "public", "host": "ny-vps.example.com"},
      "transports": ["vless-reality"]
    },
    {
      "id": "pt-home",
      "role": "exit",
      "country": "PT",
      "connectivity": {"mode": "outbound"},
      "transports": []
    }
  ]
}
```

`example_inventory()` returns this example as a fresh dictionary each time.
Example hosts are placeholders; transport declarations describe intended
capabilities and do not enable them.

## Validation rules

- The root requires only `version` and `nodes`. `version` must be integer `1`
  (a boolean or float is invalid); `nodes` must be an array. An empty inventory
  is valid.
- Every node requires `id`, `role`, and `connectivity`. Only `country` and
  `transports` are optional. Unknown fields are rejected at every object level.
- IDs are unique, stable identifiers of 1–64 ASCII characters: a lowercase
  letter or digit followed by lowercase letters, digits, underscores, or hyphens.
  Validation never generates or normalizes IDs. Preserve an ID when a host or
  role changes; changing an ID requires updating its external references.
- `role` is exactly `gateway`, `exit`, or `both`. It records intended function;
  it does not establish a topology or assert that any role is operational.
- If present, `country` must be exactly two uppercase ASCII letters, conventionally
  an ISO country code such as `RU`, `US`, or `PT`. Only syntax is checked;
  membership in a country registry is not checked. Omit unknown countries.
- `connectivity` requires `mode`, exactly `public` or `outbound`. Its only
  optional field is `host`. The host may be omitted in **either** mode. A public
  declaration records intended inbound reachability; outbound records a node
  expected to initiate future connectivity, including home nodes behind CGNAT.
- A supplied host must be a nonempty ASCII DNS hostname, IPv4 address, or bare
  IPv6 address. DNS names may end in a trailing dot. URLs, ports, userinfo,
  whitespace, paths, query strings, IPv6 brackets and zone IDs are rejected.
  Validation is syntactic: private/CGNAT addresses are allowed, and neither DNS
  resolution nor public reachability is verified.
- `transports`, if present, is an array of unique identifiers with the same
  syntax and length bound as node IDs. An empty array is valid. Names such as
  `vless-reality` or `wireguard` are descriptive labels, not runtime configuration
  or a fixed list of supported implementations.
- Optional values must be omitted rather than set to `null`. No credential
  fields are permitted. A recursive scan rejects secret fields even inside
  unknown nested objects or arrays, including `uuid`, `client_uuid`, passwords,
  tokens, credentials, and private keys, with case and separator variants.
  A node's `id` is allowed, including a UUID-shaped ID; an authentication `uuid`
  field is forbidden. Other unknown fields are rejected by the strict schema.

Inventory stores **no credentials**. Keep client authentication UUIDs, passwords,
private keys, upstream links, and connection configuration outside it. The
validator enforces field names and structural constraints, not arbitrary secret
recognition inside otherwise valid metadata strings. Do not place secrets in
IDs, hostnames, or transport names. Even credential-free infrastructure metadata
may be private; choose where to store or share it accordingly.

## Python API

```python
import json
from vpn_inventory import (
    example_inventory,
    summary_nodes,
    validate_inventory,
    validate_node_references,
)

inventory = example_inventory()  # Or json.loads(your_separate_json_document).
validate_inventory(inventory)   # Returns None; never changes the input.
rows = summary_nodes(inventory)
validate_node_references(inventory, ["ru-vps", "pt-home"])
print(json.dumps(rows, indent=2))
```

`validate_inventory(dict) -> None` raises `InventoryError`, a `ValueError`
subclass, for invalid input. Messages identify schema locations without
including supplied values or unknown field names. Cyclic containers and
non-string dictionary keys in Python inputs are rejected too.

`summary_nodes(dict) -> list[dict]` validates first, then returns fresh rows in
inventory order containing exactly `id`, `role`, `country`, `mode`, `host`, and
`transports`. Missing country and host become `None`; missing transports become
an independent empty list. Modifying a row or its transports does not modify the
inventory. Invalid or credential-bearing inventories raise rather than produce
a partial summary. Rows are structured data; callers must escape for their
display context.

`validate_node_references(dict, list[str]) -> None` validates the inventory and
checks that each external reference names an existing node. Empty or repeated
references are allowed. Unknown or malformed IDs raise `InventoryError`.
References are deliberately separate from the inventory schema; this helper
does not validate topology, role compatibility, or actual connectivity.

## CLI and runtime references

```sh
python3 vpnctl.py inventory example --file data/inventory.json
python3 vpnctl.py inventory validate --file data/inventory.json
python3 vpnctl.py inventory list --file data/inventory.json
python3 vpnctl.py upstream bind ny-reality --node ny-vps --inventory data/inventory.json
python3 vpnctl.py upstream bind ny-cdn --node ny-vps --inventory data/inventory.json
python3 vpnctl.py inventory validate --file data/inventory.json --with-runtime
```

Example creation refuses to overwrite an existing file. Replace placeholder
hosts before using it as an operational inventory. Set the local runtime node
ID/role explicitly with the existing node command before --with-runtime checks.
Runtime state stores only stable references in `upstream_nodes`; transport
credentials remain in runtime upstream definitions, outside inventory.
Multiple transport IDs can reference the same exit node. Bindings require an
exit/both node and reject gateway-only nodes. With-runtime validation checks
local identity, role compatibility and references, without provisioning anything.

All inventory operations are local. No SSH, server deletion/rotation, cloud
resources, tunnels, 3x-ui database integration, or automatic key replacement is
implemented. The Python CLI and its independent JSON state remain authoritative.
Gateway and exit provisioning can be introduced independently later.

## Compatibility and rollback

This adds optional v4 metadata and a separate version-1 inventory file; rendered
Xray config, client UUIDs, links, keys, quotas and accounting do not change.
Back up both files privately before manual edits. To roll back to the PR 4 tag,
stop inventory-related automation if any, retain/archive the inventory file and
remove optional `upstream_nodes` metadata if desired; PR 4 does not use it.
Do not regenerate state or run provisioning scripts to remove inventory.
The `pr-5-node-inventory` tag groups this preparation and its tests.

## Tests

```bash
python3 -B -m unittest discover -s tests -p 'test_inventory.py' -v
```

Tests cover strict types and fields, IDs, hosts, outbound/CGNAT metadata,
recursive credential rejection, safe summaries, independent examples, external
references, and loading the module without runtime or third-party packages.
