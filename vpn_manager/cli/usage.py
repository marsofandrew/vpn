import argparse

from vpn_manager import accounting as app_accounting
from vpn_manager import clock as app_clock
from vpn_manager import values as app_values
from vpn_manager.state import model as app_state_model


def command_quota_set(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    app_accounting.ensure_monthly_period(state)
    profile, client = app_state_model.require_client(
        state, args.name_or_id, args.profile
    )
    client["quota_bytes"] = app_values.parse_size(args.quota)
    client["updated_at"] = app_clock.utc_now()
    persist(state, args.state, args.config)
    print(
        f"Monthly quota for {app_state_model.profile_label(profile)}/{client['name']} set to {app_values.format_size(client['quota_bytes'])}"
    )


def command_quota_reset(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    app_accounting.ensure_monthly_period(state)
    profile, client = app_state_model.require_client(
        state, args.name_or_id, args.profile
    )
    client["used_uplink_bytes"] = 0
    client["used_downlink_bytes"] = 0
    if args.enable:
        client["enabled"] = True
        client["disabled_reason"] = None
    client["updated_at"] = app_clock.utc_now()
    persist(
        state,
        args.state,
        args.config,
        args.compose_file,
        restart=args.enable and not args.no_restart,
    )
    print(
        f"Monthly usage reset for {app_state_model.profile_label(profile)}/{client['name']} in period {state['usage_period']}"
    )


def command_quota_enforce(args: argparse.Namespace, *, persist, sample, store) -> None:
    state = store.load(args.state)
    period_changed = app_accounting.ensure_monthly_period(state)
    sample(state, args.compose_file)
    disabled = app_accounting.enforce_quotas(state)
    persist(
        state,
        args.state,
        args.config,
        args.compose_file,
        restart=not args.no_restart,
    )
    profile_by_client_id = {
        client["id"]: profile
        for profile in app_state_model.all_profiles(state)
        for client in profile.get("clients", [])
    }
    for client in disabled:
        used = int(client.get("used_uplink_bytes", 0)) + int(
            client.get("used_downlink_bytes", 0)
        )
        profile = profile_by_client_id[client["id"]]
        print(
            f"Disabled {app_state_model.profile_label(profile)}/{client['name']} after {app_values.format_size(used)} used"
        )
    if period_changed:
        print(f"Monthly quota period rolled over to {state['usage_period']}.")
    if not disabled:
        print("No clients exceeded quota.")


def command_usage(args: argparse.Namespace, *, persist, sample, store) -> None:
    state = store.load(args.state)
    period_changed = app_accounting.ensure_monthly_period(state)
    if args.refresh:
        sample(state, args.compose_file)
        period_changed = True
    if period_changed:
        persist(state, args.state, args.config)
    profiles = (
        [app_state_model.require_profile(state, args.profile)]
        if args.profile
        else app_state_model.all_profiles(state)
    )
    for profile in profiles:
        for client in profile.get("clients", []):
            uplink = int(client.get("used_uplink_bytes", 0))
            downlink = int(client.get("used_downlink_bytes", 0))
            print(
                f"{app_state_model.profile_label(profile)}/{client['name']}\tuplink={app_values.format_size(uplink)}\tdownlink={app_values.format_size(downlink)}"
                f"\ttotal={app_values.format_size(uplink + downlink)}\tperiod={state['usage_period']}"
                f"\tmonthly_quota={app_values.format_size(client.get('quota_bytes'))}"
            )
