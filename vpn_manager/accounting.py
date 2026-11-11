from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vpn_manager import clock as app_clock
from vpn_manager import errors as app_errors
from vpn_manager.ports import Calendar, Statistics
from vpn_manager.state import model as app_state_model
from vpn_manager.xray import runtime as app_xray_runtime


def ensure_monthly_period(state: dict[str, Any], period: str | None = None) -> bool:
    period = period if period is not None else app_clock.current_usage_period()
    existing_period = state.get("usage_period")
    if existing_period is None:
        state["usage_period"] = period
        return True
    if existing_period == period:
        return False

    now = app_clock.utc_now()
    state["usage_period"] = period
    for client in app_state_model.clients_in_state(state):
        client["used_uplink_bytes"] = 0
        client["used_downlink_bytes"] = 0
        if client.get("disabled_reason") == "quota_exceeded":
            client["enabled"] = True
            client["disabled_reason"] = None
        client["updated_at"] = now
    return True


def sample_usage(state: dict[str, Any], compose_file: Path) -> None:
    UsageService(app_xray_runtime.XrayStatistics(), app_clock.SystemCalendar()).sample(
        state, compose_file
    )


@dataclass
class UsageService:
    statistics: Statistics
    calendar: Calendar

    def sample(self, state: dict[str, Any], compose_file: Path) -> None:
        before = self.statistics.epoch(compose_file)
        stats = self.statistics.read(compose_file, state)
        if self.statistics.epoch(compose_file) != before:
            raise app_errors.VpnctlError(
                "Xray restarted during statistics read; retry the command"
            )
        ensure_monthly_period(state, self.calendar.period())
        apply_usage_snapshot(state, collect_usage_deltas(stats), before)


def apply_usage_snapshot(
    state: dict[str, Any], counters: dict[str, dict[str, int]], epoch: str
) -> None:
    accounting = state.setdefault("accounting", {"epoch": epoch, "checkpoints": {}})
    same_epoch = accounting.get("epoch") == epoch
    checkpoints = accounting.get("checkpoints", {}) if same_epoch else {}
    deltas = {}
    for email, traffic in counters.items():
        previous = checkpoints.get(email, {})
        deltas[email] = {}
        for direction, value in traffic.items():
            if value < 0:
                raise app_errors.VpnctlError("negative Xray traffic counter")
            baseline = int(previous.get(direction, 0))
            deltas[email][direction] = value - baseline if value >= baseline else value
        checkpoints[email] = traffic.copy()
    apply_usage_deltas(state, deltas)
    state["accounting"] = {"epoch": epoch, "checkpoints": checkpoints}


def stat_entries(stats_response: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(stats_response.get("stat"), list):
        return stats_response["stat"]
    if isinstance(stats_response.get("stats"), list):
        return stats_response["stats"]
    return []


def collect_usage_deltas(stats_response: dict[str, Any]) -> dict[str, dict[str, int]]:
    deltas: dict[str, dict[str, int]] = {}
    for entry in stat_entries(stats_response):
        name = entry.get("name", "")
        value = int(entry.get("value") or 0)
        parts = name.split(">>>")
        if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
            continue
        email = parts[1]
        direction = parts[3]
        if direction not in {"uplink", "downlink"}:
            continue
        deltas.setdefault(email, {"uplink": 0, "downlink": 0})[direction] += value
    return deltas


def apply_usage_deltas(
    state: dict[str, Any], deltas: dict[str, dict[str, int]]
) -> bool:
    changed = False
    clients_by_email = {
        client["email"]: client for client in app_state_model.clients_in_state(state)
    }
    for email, traffic in deltas.items():
        client = clients_by_email.get(email)
        if client is None:
            continue
        uplink = int(traffic.get("uplink", 0))
        downlink = int(traffic.get("downlink", 0))
        if uplink or downlink:
            client["used_uplink_bytes"] = (
                int(client.get("used_uplink_bytes", 0)) + uplink
            )
            client["used_downlink_bytes"] = (
                int(client.get("used_downlink_bytes", 0)) + downlink
            )
            client["updated_at"] = app_clock.utc_now()
            changed = True
    return changed


def enforce_quotas(state: dict[str, Any]) -> list[dict[str, Any]]:
    disabled: list[dict[str, Any]] = []
    now = app_clock.utc_now()
    for client in app_state_model.clients_in_state(state):
        quota = client.get("quota_bytes")
        used = int(client.get("used_uplink_bytes", 0)) + int(
            client.get("used_downlink_bytes", 0)
        )
        if client.get("enabled", True) and quota is not None and used >= int(quota):
            client["enabled"] = False
            client["disabled_reason"] = "quota_exceeded"
            client["updated_at"] = now
            disabled.append(client)
    return disabled
