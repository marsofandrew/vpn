import argparse
from pathlib import Path

import vpn_subscriptions
from vpn_manager import errors as app_errors
from vpn_manager.exports import links as app_exports_links
from vpn_manager.state import model as app_state_model


def command_endpoint(args: argparse.Namespace, *, store) -> None:
    state = store.load(args.state)
    try:
        if args.endpoint_command == "add":
            vpn_subscriptions.add_endpoint(state, args.name, args.client, args.link)
            store.save(args.state, state)
        elif args.endpoint_command == "remove":
            vpn_subscriptions.remove_endpoint(state, args.name)
            store.save(args.state, state)
        else:
            for name, entry in state.get("client_entries", {}).items():
                endpoint = entry["endpoint"]
                print(
                    f"{name}\tclient={entry['client']}\taddress={endpoint['address']}"
                    f"\ttransport={endpoint['transport']['type']}\tsecurity={endpoint['security']['type']}"
                )
    except ValueError as error:
        raise app_errors.VpnctlError(str(error)) from None


def command_subscription(args: argparse.Namespace, *, store) -> None:
    state = store.load(args.state)
    local_links = [
        app_exports_links.generate_vless_link(client, state, profile)
        for profile in app_state_model.all_profiles(state)
        for client in profile.get("clients", [])
        if client["name"] == args.client and client.get("enabled", True)
    ]
    try:
        content = vpn_subscriptions.subscription_text(state, args.client, local_links)
        try:
            protected = protected_runtime_paths(
                args.state, args.config, args.compose_file
            )
            output = args.output.resolve()
        except (OSError, RuntimeError):
            raise app_errors.VpnctlError(
                "cannot resolve subscription output or runtime paths"
            ) from None
        if output in protected:
            raise app_errors.VpnctlError(
                "subscription output cannot overwrite state or runtime files"
            )
        vpn_subscriptions.private_write(args.output, content)
    except ValueError as error:
        raise app_errors.VpnctlError(str(error)) from None
    print(f"Private subscription written to {args.output}")


def protected_runtime_paths(
    state_path: Path, config_path: Path, compose_file: Path
) -> set[Path]:
    paths = {state_path, config_path, compose_file}
    for source in (state_path, config_path):
        paths.update(
            source.with_name(source.name + suffix)
            for suffix in (
                ".bak",
                ".v3.bak",
                ".deploy",
                ".candidate",
                ".pending",
                ".lock",
            )
        )
    return {path.resolve() for path in paths}
