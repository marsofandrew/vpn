import argparse

import vpn_transports
from vpn_manager import errors as app_errors
from vpn_manager import settings as app_settings
from vpn_manager import values as app_values
from vpn_manager.state import model as app_state_model


def command_upstream_show(args: argparse.Namespace, *, store) -> None:
    state = store.load(args.state)
    name = getattr(args, "name", app_settings.UPSTREAM_OUTBOUND_TAG)
    upstream = state["upstreams"].get(name)
    if not upstream:
        print("No upstream configured.")
        return
    print(
        f"{name}\thost={upstream['address']}\tport={upstream['port']}"
        f"\ttransport={upstream['transport']['type']}\tsecurity={upstream['security']['type']}"
        f"\tenabled={upstream.get('enabled', True)}"
    )


def command_upstream_set(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    name = app_values.validate_stable_name(
        getattr(args, "name", app_settings.UPSTREAM_OUTBOUND_TAG)
    )
    if getattr(args, "upstream_command", "set") == "add" and name in state["upstreams"]:
        raise app_errors.VpnctlError("upstream already exists")
    try:
        state["upstreams"][name] = vpn_transports.parse_link(args.link)
    except ValueError as error:
        raise app_errors.VpnctlError(str(error)) from None
    state.setdefault("health", {}).pop(name, None)
    state["routing_policies"].setdefault(
        name, {"type": "upstream", "upstreams": [name]}
    )
    persist(
        state, args.state, args.config, args.compose_file, restart=not args.no_restart
    )
    print(f"Upstream saved: {name}")


def command_upstream_clear(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    name = getattr(args, "name", app_settings.UPSTREAM_OUTBOUND_TAG)
    assigned = {profile["route"] for profile in app_state_model.all_profiles(state)}
    if any(
        name in policy.get("upstreams", []) and policy_name in assigned
        for policy_name, policy in state["routing_policies"].items()
    ):
        raise app_errors.VpnctlError("cannot remove an assigned upstream")
    state["upstreams"].pop(name, None)
    state.setdefault("upstream_nodes", {}).pop(name, None)
    state["routing_policies"] = {
        key: policy
        for key, policy in state["routing_policies"].items()
        if name not in policy.get("upstreams", [])
    }
    persist(
        state, args.state, args.config, args.compose_file, restart=not args.no_restart
    )
    print("Upstream cleared.")


def command_upstream_list(args: argparse.Namespace, *, store) -> None:
    for name in store.load(args.state)["upstreams"]:
        args.name = name
        command_upstream_show(args, store=store)


def command_upstream_enabled(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    if args.name not in state["upstreams"]:
        raise app_errors.VpnctlError("unknown upstream")
    state["upstreams"][args.name]["enabled"] = args.upstream_command == "enable"
    persist(
        state, args.state, args.config, args.compose_file, restart=not args.no_restart
    )


def command_route(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    profile = app_state_model.require_profile(state, args.profile)
    if args.route_command == "set":
        if args.policy not in state["routing_policies"]:
            raise app_errors.VpnctlError("unknown routing policy")
        profile["route"] = args.policy
        profile["outbound_mode"] = (
            "direct"
            if state["routing_policies"][args.policy]["type"] == "direct"
            else "proxy"
        )
        persist(
            state,
            args.state,
            args.config,
            args.compose_file,
            restart=not args.no_restart,
        )
    print(f"{app_state_model.profile_label(profile)}\tpolicy={profile['route']}")


def command_policy(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    if args.policy_command == "list":
        for name, policy in state["routing_policies"].items():
            print(
                f"{name}\ttype={policy['type']}\tmembers={','.join(policy.get('upstreams', []))}"
            )
        return
    name = app_values.validate_stable_name(args.name)
    if name in {"direct", "block"}:
        raise app_errors.VpnctlError("built-in policies cannot be replaced")
    policy = {"type": args.type}
    if args.type in {"upstream", "priority", "balanced"}:
        policy["upstreams"] = args.upstream or []
        policy["cooldown"] = args.cooldown
    state["routing_policies"][name] = policy
    persist(
        state, args.state, args.config, args.compose_file, restart=not args.no_restart
    )


def command_node(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    state["node"] = {
        "id": app_values.validate_stable_name(args.id),
        "role": args.role,
        "foreign_only": args.foreign_only,
    }
    persist(
        state, args.state, args.config, args.compose_file, restart=not args.no_restart
    )
