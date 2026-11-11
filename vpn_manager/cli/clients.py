import argparse

from vpn_manager import accounting as app_accounting
from vpn_manager import clock as app_clock
from vpn_manager import errors as app_errors
from vpn_manager import values as app_values
from vpn_manager.exports import links as app_exports_links
from vpn_manager.state import creation as app_state_creation
from vpn_manager.state import model as app_state_model


def command_client_add(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    app_accounting.ensure_monthly_period(state)
    profile = app_state_model.require_profile(state, args.profile)
    if app_state_model.find_client(
        state, args.name, app_state_model.profile_label(profile)
    ):
        raise app_errors.VpnctlError(
            f"client already exists in profile {app_state_model.profile_label(profile)}: {args.name}"
        )
    client = app_state_creation.create_client(
        args.name,
        state["default_domain"],
        app_values.parse_size(args.quota),
        app_state_model.profile_label(profile),
    )
    profile["clients"].append(client)
    profile["updated_at"] = app_clock.utc_now()
    persist(
        state, args.state, args.config, args.compose_file, restart=not args.no_restart
    )
    print(f"Client added: {app_state_model.profile_label(profile)}/{client['name']}")
    print(app_exports_links.generate_vless_link(client, state, profile))


def command_client_remove(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    app_accounting.ensure_monthly_period(state)
    profile, client = app_state_model.require_client(
        state, args.name_or_id, args.profile
    )
    profile["clients"] = [
        item for item in profile["clients"] if item["id"] != client["id"]
    ]
    profile["updated_at"] = app_clock.utc_now()
    persist(
        state, args.state, args.config, args.compose_file, restart=not args.no_restart
    )
    print(f"Client removed: {app_state_model.profile_label(profile)}/{client['name']}")


def command_client_list(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    if app_accounting.ensure_monthly_period(state):
        persist(state, args.state, args.config)
    profiles = (
        [app_state_model.require_profile(state, args.profile)]
        if args.profile
        else app_state_model.all_profiles(state)
    )
    clients = [
        (profile, client)
        for profile in profiles
        for client in profile.get("clients", [])
    ]
    if not clients:
        print("No clients configured.")
        return
    for profile, client in clients:
        used = int(client.get("used_uplink_bytes", 0)) + int(
            client.get("used_downlink_bytes", 0)
        )
        status = (
            "enabled"
            if client.get("enabled", True)
            else f"disabled:{client.get('disabled_reason')}"
        )
        print(
            f"{app_state_model.profile_label(profile)}/{client['name']}\t{status}\tport={profile['port']}\tperiod={state['usage_period']}"
            f"\tmonthly_quota={app_values.format_size(client.get('quota_bytes'))}"
            f"\tused={app_values.format_size(used)}\tid={client['id']}"
        )


def command_client_enabled(
    args: argparse.Namespace, enabled: bool, *, persist, store
) -> None:
    state = store.load(args.state)
    app_accounting.ensure_monthly_period(state)
    profile, client = app_state_model.require_client(
        state, args.name_or_id, args.profile
    )
    client["enabled"] = enabled
    client["disabled_reason"] = None if enabled else args.reason
    client["updated_at"] = app_clock.utc_now()
    profile["updated_at"] = app_clock.utc_now()
    persist(
        state, args.state, args.config, args.compose_file, restart=not args.no_restart
    )
    print(
        f"Client {'enabled' if enabled else 'disabled'}: {app_state_model.profile_label(profile)}/{client['name']}"
    )


def command_link(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    if app_accounting.ensure_monthly_period(state):
        persist(state, args.state, args.config)
    profile, client = app_state_model.require_client(
        state, args.name_or_id, args.profile
    )
    link = app_exports_links.generate_vless_link(client, state, profile)
    print(link)
    if args.qr:
        path = app_exports_links.write_qr(
            link,
            f"{app_state_model.profile_label(profile)}-{client['name']}",
            args.output,
        )
        print(f"QR code saved to {path}")


def command_client_enable(args, *, persist, store):
    command_client_enabled(args, True, persist=persist, store=store)


def command_client_disable(args, *, persist, store):
    command_client_enabled(args, False, persist=persist, store=store)
