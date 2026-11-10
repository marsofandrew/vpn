"""Nonmutating structural checks for v4 state, before semantic validation.

Unknown metadata is retained. Defaulted fields may be absent, but present
fields must have their command-compatible types. Transport semantics remain
the responsibility of vpn_transports. Paths use positions instead of stored
mapping keys so errors never disclose credentials or operator-provided names.
"""

import math


def _object(value: object, path: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(path + " must be an object")
    return value


def _list(value, path):
    if not isinstance(value, list):
        raise ValueError(path + " must be a list")
    return value


def _string(value, path):
    if not isinstance(value, str):
        raise ValueError(path + " must be a string")


def _boolean(value, path):
    if type(value) is not bool:
        raise ValueError(path + " must be a boolean")


def _integer(value, path, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(path + " must be an integer at least " + str(minimum))


def _number(value, path, positive=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(path + " must be a finite nonnegative number")
    try:
        valid = math.isfinite(value) and (value > 0 if positive else value >= 0)
    except OverflowError:
        valid = False
    if not valid:
        requirement = "positive" if positive else "nonnegative"
        raise ValueError(path + " must be a finite " + requirement + " number")


def _required(record, field, path, check):
    field_path = path + "." + field
    if field not in record:
        raise ValueError(field_path + " is required")
    check(record[field], field_path)


def _optional(record, fields, path, check, nullable=False):
    for field in fields:
        if field in record and not (nullable and record[field] is None):
            check(record[field], path + "." + field)


def _records(value, path):
    for index, (key, record) in enumerate(_object(value, path).items()):
        record_path = f"{path}[{index}]"
        _string(key, record_path + ".key")
        yield _object(record, record_path), record_path


def _strings(value, path):
    for index, item in enumerate(_list(value, path)):
        _string(item, f"{path}[{index}]")


def _stream(record, path):
    _required(record, "type", path, _string)
    _optional(record, ("settings",), path, _object)


def _endpoint(record, path):
    for field in ("protocol", "address"):
        _required(record, field, path, _string)
    _required(record, "port", path, _port)
    _required(record, "auth", path, _object)
    _required(record["auth"], "id", path + ".auth", _string)
    _optional(record["auth"], ("flow", "encryption"), path + ".auth", _string)
    for field in ("transport", "security"):
        _required(record, field, path, _object)
        _stream(record[field], path + "." + field)
    _required(record["security"], "settings", path + ".security", _object)
    _optional(record, ("enabled",), path, _boolean)


def _port(value, path):
    _integer(value, path, 1)
    if value > 65535:
        raise ValueError(path + " must be at most 65535")


def _client(record, path):
    for field in ("name", "id", "email"):
        _required(record, field, path, _string)
    _optional(record, ("enabled",), path, _boolean)
    _optional(record, ("quota_bytes",), path, _integer, nullable=True)
    _optional(record, ("used_uplink_bytes", "used_downlink_bytes"), path, _integer)
    _optional(record, ("created_at", "updated_at"), path, _string)
    _optional(record, ("disabled_reason",), path, _string, nullable=True)


def _profile(record, path):
    _optional(
        record,
        (
            "name",
            "route",
            "outbound_mode",
            "created_at",
            "updated_at",
            "client_ech_config_list",
        ),
        path,
        _string,
    )
    _required(record, "port", path, _port)
    for field in ("reality_target", "short_id"):
        _required(record, field, path, _string)
    _required(record, "keys", path, _object)
    keys = record["keys"]
    _required(keys, "public_key", path + ".keys", _string)
    if "private_key" not in keys:
        raise ValueError(path + ".keys.private_key is required")
    _optional(record, ("transport", "security"), path, _object)
    for field in ("transport", "security"):
        if field in record:
            _stream(record[field], path + "." + field)
    if "security" in record:
        _required(record["security"], "settings", path + ".security", _object)
    if (
        keys["private_key"] is not None
        or record.get("security", {}).get("type") != "tls"
    ):
        _string(keys["private_key"], path + ".keys.private_key")
    for index, client in enumerate(_list(record.get("clients", []), path + ".clients")):
        client_path = f"{path}.clients[{index}]"
        _client(_object(client, client_path), client_path)


def _health(record, path):
    _optional(record, ("status",), path, _string)
    _optional(record, ("error",), path, _string, nullable=True)
    _optional(record, ("success", "exit_ip_verified"), path, _boolean)
    _optional(
        record,
        ("consecutive_failures", "consecutive_successes", "body_bytes"),
        path,
        _integer,
    )
    _optional(record, ("next_probe_at",), path, _number)
    _optional(
        record,
        (
            "last_probe",
            "last_success",
            "restored_at",
            "latency_ms",
            "download_time_ms",
            "total_time_ms",
            "throughput_bps",
        ),
        path,
        _number,
        nullable=True,
    )
    _optional(
        record, ("status_code", "egress_status_code"), path, _integer, nullable=True
    )


def _health_settings(record, path):
    _optional(record, ("download_url", "egress_url"), path, _string)
    _optional(record, ("expected_exit_ips",), path, _strings)
    for field in ("interval", "timeout"):
        if field in record:
            _number(record[field], path + "." + field, positive=True)
    _optional(record, ("cooldown",), path, _number)
    for field in ("fail_threshold", "success_threshold", "bytes_required"):
        if field in record:
            _integer(record[field], path + "." + field, 1)


def validate_state_shape(state: object) -> None:
    """Raise ValueError with a data-free field path for malformed v4 state."""
    state = _object(state, "state")
    _required(state, "version", "state", _integer)
    for field in ("server_host", "default_domain"):
        _required(state, field, "state", _string)
    _optional(
        state,
        ("created_at", "updated_at", "fingerprint", "flow", "spider_x"),
        "state",
        _string,
    )
    _optional(state, ("usage_period",), "state", _string, nullable=True)
    _required(state, "node", "state", _object)
    for field in ("id", "role"):
        _required(state["node"], field, "state.node", _string)
    _optional(state["node"], ("foreign_only",), "state.node", _boolean)
    for field in ("upstreams", "routing_policies"):
        _required(state, field, "state", _object)
    for upstream, path in _records(state["upstreams"], "state.upstreams"):
        _endpoint(upstream, path)
    for policy, path in _records(state["routing_policies"], "state.routing_policies"):
        _required(policy, "type", path, _string)
        if policy["type"] in ("upstream", "balanced", "priority"):
            _required(policy, "upstreams", path, _strings)
        _optional(policy, ("upstreams",), path, _strings)
        _optional(policy, ("current_upstream",), path, _string, nullable=True)
        _optional(policy, ("cooldown",), path, _number)
    _required(state, "profiles", "state", _list)
    for index, profile in enumerate(state["profiles"]):
        path = f"state.profiles[{index}]"
        _profile(_object(profile, path), path)
    if "accounting" in state:
        accounting = _object(state["accounting"], "state.accounting")
        _optional(accounting, ("epoch",), "state.accounting", _string)
        for checkpoint, path in _records(
            accounting.get("checkpoints", {}), "state.accounting.checkpoints"
        ):
            _optional(checkpoint, ("uplink", "downlink"), path, _integer)
    for field, check in (("health", _health), ("health_settings", _health_settings)):
        if field in state:
            for record, path in _records(state[field], "state." + field):
                check(record, path)
    if "upstream_nodes" in state:
        bindings = _object(state["upstream_nodes"], "state.upstream_nodes")
        for index, (key, value) in enumerate(bindings.items()):
            path = f"state.upstream_nodes[{index}]"
            _string(key, path + ".key")
            _string(value, path)
    if "client_entries" in state:
        for entry, path in _records(state["client_entries"], "state.client_entries"):
            _required(entry, "client", path, _string)
            _required(entry, "endpoint", path, _object)
            _endpoint(entry["endpoint"], path + ".endpoint")
    if "route_events" in state:
        for index, event in enumerate(
            _list(state["route_events"], "state.route_events")
        ):
            path = f"state.route_events[{index}]"
            event = _object(event, path)
            for field in ("at", "policy", "to"):
                _required(event, field, path, _string)
            if "from" not in event:
                raise ValueError(path + ".from is required")
            _optional(event, ("from",), path, _string, nullable=True)
