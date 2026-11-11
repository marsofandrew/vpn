"""Health observations and route decisions without persistence or CLI output."""

import argparse
import ipaddress
import math
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

import vpn_health
from vpn_manager.errors import VpnctlError
from vpn_manager.ports import PathProbe
from vpn_manager.values import parse_port


def configure_probe(state, name, settings):
    if name not in state["upstreams"]:
        raise VpnctlError("unknown upstream")
    _validate_timing(settings)
    try:
        for value in (settings["download_url"], settings["egress_url"]):
            _validate_url(value)
        for address in settings["expected_exit_ips"]:
            ipaddress.ip_address(address)
    except (ValueError, argparse.ArgumentTypeError):
        raise VpnctlError(
            "probes require HTTPS URLs without credentials and literal expected exit IPs"
        ) from None
    state.setdefault("health_settings", {})[name] = settings


def _validate_timing(settings):
    interval, timeout = settings["interval"], settings["timeout"]
    if (
        not math.isfinite(interval)
        or not math.isfinite(timeout)
        or interval <= 0
        or timeout <= 0
        or settings["fail_threshold"] <= 0
        or settings["success_threshold"] <= 0
    ):
        raise VpnctlError("probe intervals, thresholds and timeout must be positive")


def _validate_url(value):
    endpoint = urlparse(value)
    if (
        endpoint.scheme != "https"
        or not endpoint.hostname
        or endpoint.username
        or endpoint.password
        or endpoint.fragment
    ):
        raise ValueError
    if endpoint.port is not None:
        parse_port(endpoint.port)


@dataclass
class HealthService:
    probe: PathProbe
    now: Callable[[], float]
    timestamp: Callable[[], str]

    def check(self, state):
        self._observe(state)
        events = self._select_routes(state)
        state["route_events"] = (state.get("route_events", []) + events)[-100:]
        return events

    def _observe(self, state):
        now = self.now()
        health = state.setdefault("health", {})
        for name, upstream in state["upstreams"].items():
            settings = state.get("health_settings", {}).get(name)
            if (
                not upstream.get("enabled", True)
                or not settings
                or health.get(name, {}).get("next_probe_at", 0) > now
            ):
                continue
            result = self.probe(upstream, settings)
            try:
                health[name] = vpn_health.record_probe(
                    health.get(name, {}), result, self.now(), settings
                )
            except ValueError as error:
                raise VpnctlError(str(error)) from None

    def _select_routes(self, state):
        events = []
        for name, policy in state["routing_policies"].items():
            if policy["type"] not in {"priority", "balanced"}:
                continue
            before = policy.get("current_upstream")
            selected = vpn_health.select_route(
                policy, state["upstreams"], state["health"], self.now()
            )
            policy["current_upstream"] = selected
            if before != selected:
                events.append(
                    {
                        "at": self.timestamp(),
                        "policy": name,
                        "from": before,
                        "to": selected or "block",
                    }
                )
        return events
