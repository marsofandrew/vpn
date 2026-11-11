import argparse
import ipaddress
import math
import time
from urllib.parse import urlparse

import vpn_health
import vpn_monitor
from vpn_manager import clock as app_clock
from vpn_manager import errors as app_errors
from vpn_manager import values as app_values
from vpn_manager.state import storage as app_state_storage
from vpn_manager.xray import deployment as app_xray_deployment
from vpn_manager.xray import runtime as app_xray_runtime


def command_health(args: argparse.Namespace) -> None:
    state = app_state_storage.load_state(args.state)
    operation = args.health_command
    if operation == "configure":
        if args.name not in state["upstreams"]:
            raise app_errors.VpnctlError("unknown upstream")
        if (
            not math.isfinite(args.interval)
            or not math.isfinite(args.timeout)
            or args.interval <= 0
            or args.fail_threshold <= 0
            or args.success_threshold <= 0
            or args.timeout <= 0
        ):
            raise app_errors.VpnctlError(
                "probe intervals, thresholds and timeout must be positive"
            )
        try:
            for value in (args.download_url, args.egress_url):
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
                    app_values.parse_port(endpoint.port)
            for address in args.expected_exit_ip:
                ipaddress.ip_address(address)
        except (ValueError, argparse.ArgumentTypeError):
            raise app_errors.VpnctlError(
                "probes require HTTPS URLs without credentials and literal expected exit IPs"
            ) from None
        state.setdefault("health_settings", {})[args.name] = {
            "download_url": args.download_url,
            "egress_url": args.egress_url,
            "expected_exit_ips": args.expected_exit_ip,
            "interval": args.interval,
            "fail_threshold": args.fail_threshold,
            "success_threshold": args.success_threshold,
            "timeout": args.timeout,
            "bytes_required": args.bytes_required,
        }
        app_state_storage.save_state(args.state, state)
        return
    if operation == "events":
        for event in state.get("route_events", []):
            print(
                f"{event['at']}\t{event['policy']}\t{event['from'] or 'block'} -> {event['to']}"
            )
        return
    if operation == "check":
        now = time.time()
        health = state.setdefault("health", {})
        for name, upstream in state["upstreams"].items():
            settings = state.get("health_settings", {}).get(name)
            if (
                not upstream.get("enabled", True)
                or not settings
                or health.get(name, {}).get("next_probe_at", 0) > now
            ):
                continue
            result = vpn_monitor.probe_upstream(
                upstream,
                settings,
                args.compose_file,
                args.config.parent,
                app_xray_runtime.run_compose,
            )
            try:
                health[name] = vpn_health.record_probe(
                    health.get(name, {}), result, time.time(), settings
                )
            except ValueError as error:
                raise app_errors.VpnctlError(str(error)) from None
        events = []
        for name, policy in state["routing_policies"].items():
            if policy["type"] not in {"priority", "balanced"}:
                continue
            before = policy.get("current_upstream")
            selected = vpn_health.select_route(
                policy, state["upstreams"], health, time.time()
            )
            policy["current_upstream"] = selected
            if before != selected:
                events.append(
                    {
                        "at": app_clock.utc_now(),
                        "policy": name,
                        "from": before,
                        "to": selected or "block",
                    }
                )
        state["route_events"] = (state.get("route_events", []) + events)[-100:]
        app_xray_deployment.persist_state_and_config(
            state,
            args.state,
            args.config,
            args.compose_file,
            restart=not args.no_restart,
        )
        for event in events:
            print(
                f"Route switch: {event['policy']} {event['from'] or 'block'} -> {event['to']}"
            )
    for name, upstream in state["upstreams"].items():
        record = state.get("health", {}).get(name, {})
        print(
            f"{name}\tenabled={upstream.get('enabled', True)}\tstatus={record.get('status', 'unknown')}"
            f"\tfailures={record.get('consecutive_failures', 0)}\tlast_success={record.get('last_success')}"
            f"\tlast_probe={record.get('last_probe')}\terror={record.get('error')}"
            f"\tlatency_ms={record.get('latency_ms')}\tthroughput_bps={record.get('throughput_bps')}"
            f"\ttransfer_ms={record.get('download_time_ms')}\tbody_bytes={record.get('body_bytes')}"
        )
    for name, policy in state["routing_policies"].items():
        if policy["type"] in {"priority", "balanced"}:
            print(
                f"policy={name}\tselected={policy.get('current_upstream') or 'block'}"
            )
