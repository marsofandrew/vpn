"""Adapt health CLI input and format health status output."""

from vpn_manager.health.service import configure_probe


def command_health(args, *, store, persist, monitoring):
    state = store.load(args.state)
    if args.health_command == "configure":
        configure_probe(state, args.name, _probe_settings(args))
        store.save(args.state, state)
        return
    if args.health_command == "events":
        _print_events(state.get("route_events", []))
        return
    if args.health_command == "check":
        events = monitoring(args.compose_file, args.config.parent).check(state)
        persist(
            state,
            args.state,
            args.config,
            args.compose_file,
            restart=not args.no_restart,
        )
        _print_switches(events)
    _print_status(state)


def _probe_settings(args):
    return {
        "download_url": args.download_url,
        "egress_url": args.egress_url,
        "expected_exit_ips": args.expected_exit_ip,
        "interval": args.interval,
        "fail_threshold": args.fail_threshold,
        "success_threshold": args.success_threshold,
        "timeout": args.timeout,
        "bytes_required": args.bytes_required,
    }


def _print_events(events):
    for event in events:
        print(
            f"{event['at']}\t{event['policy']}\t{event['from'] or 'block'} -> {event['to']}"
        )


def _print_switches(events):
    for event in events:
        print(
            f"Route switch: {event['policy']} {event['from'] or 'block'} -> {event['to']}"
        )


def _print_status(state):
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
