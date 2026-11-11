import math

from vpn_manager.health.fields import _ERROR_CODES, _METRICS, _integer, _number


def select_route(policy: dict, upstreams: dict, health: dict, now: float) -> str | None:
    """Return an eligible stable ID; see module docstring for policy fields."""
    now = _number(now, "now")
    kind = policy.get("type")
    if kind in ("direct", "block"):
        return None
    if kind not in ("upstream", "priority", "balanced"):
        raise ValueError("unsupported policy type")
    members = policy.get("upstreams", [])
    if (
        not isinstance(members, list)
        or any(not isinstance(x, str) for x in members)
        or len(set(members)) != len(members)
        or (kind == "upstream" and len(members) != 1)
    ):
        raise ValueError("invalid policy upstreams")
    candidates = [
        uid
        for uid in members
        if uid in upstreams
        and upstreams[uid].get("enabled", True)
        and health.get(uid, {}).get("status") == "healthy"
    ]
    if not candidates:
        return None
    if kind == "balanced":
        return min(candidates, key=lambda uid: _latency(health, uid))
    if kind == "priority":
        return _priority(policy, candidates, health, now)
    return candidates[0]


def _latency(health, uid):
    value = health[uid].get("latency_ms")
    try:
        return _number(value, "latency_ms", 0)
    except ValueError:
        return math.inf


def _priority(policy, candidates, health, now):
    cooldown = _number(policy.get("cooldown", 60), "cooldown", 0)
    current = policy.get("current_upstream")
    if current in candidates:
        for uid in candidates[: candidates.index(current)]:
            restored = health[uid].get("restored_at")
            if cooldown == 0:
                return uid
            if restored is not None:
                restored = _number(restored, "restored_at")
                if now - restored >= cooldown:
                    return uid
        return current
    return candidates[0]


def record_probe(previous: dict, result: dict, now: float, config: dict) -> dict:
    """Apply one observation; interval schedules the next call, not this one."""
    now = _number(now, "now")
    interval = _number(config.get("interval", 30), "interval", 0)
    _number(config.get("cooldown", 60), "cooldown", 0)
    fail_threshold = _integer(config.get("fail_threshold", 3), "fail_threshold")
    success_threshold = _integer(
        config.get("success_threshold", 3), "success_threshold"
    )
    if previous.get("last_probe") is not None and now < _number(
        previous["last_probe"], "last_probe"
    ):
        raise ValueError("out of order probe")
    status = previous.get("status", "unknown")
    if status not in ("unknown", "healthy", "unhealthy"):
        raise ValueError("invalid health status")
    verified = result.get("exit_ip_verified") is True
    unverified = result.get("success") is True and not verified
    success = result.get("success") is True and verified
    failures = (
        0
        if success
        else _integer(previous.get("consecutive_failures", 0), "failures", 0) + 1
    )
    successes = (
        _integer(previous.get("consecutive_successes", 0), "successes", 0) + 1
        if success
        else 0
    )
    restored_at = previous.get("restored_at")
    if success and successes >= success_threshold and status != "healthy":
        status, restored_at = "healthy", now
    elif not success and failures >= fail_threshold:
        status, restored_at = "unhealthy", None
    state = _observation(
        previous,
        result,
        now,
        interval,
        status,
        success,
        failures,
        successes,
        restored_at,
        verified,
        unverified,
    )
    _probe_metrics(state, result)
    return state


def _observation(
    previous,
    result,
    now,
    interval,
    status,
    success,
    failures,
    successes,
    restored_at,
    verified,
    unverified,
):
    state = {
        "status": status,
        "success": success,
        "consecutive_failures": failures,
        "consecutive_successes": successes,
        "last_probe": now,
        "next_probe_at": _number(now + interval, "next_probe_at"),
        "last_success": now if success else previous.get("last_success"),
        "restored_at": restored_at,
        "error": None
        if success
        else "exit_ip_unverified"
        if unverified
        else (
            result.get("error")
            if isinstance(result.get("error"), str) and result["error"] in _ERROR_CODES
            else "probe_failed"
        ),
        "exit_ip_verified": verified,
    }
    return state


def _probe_metrics(state, result):
    for key in _METRICS:
        try:
            state[key] = _number(result.get(key), key, 0)
        except ValueError:
            state[key] = None
    for key in ("status_code", "egress_status_code", "body_bytes"):
        value = result.get(key)
        valid = (
            isinstance(value, int)
            and not isinstance(value, bool)
            and (value >= 0 if key == "body_bytes" else 100 <= value <= 599)
        )
        state[key] = value if valid else (0 if key == "body_bytes" else None)
