import argparse

from vpn_manager import accounting as app_accounting
from vpn_manager import errors as app_errors
from vpn_manager import files as app_files
from vpn_manager import values as app_values
from vpn_manager.exports import links as app_exports_links
from vpn_manager.state import creation as app_state_creation
from vpn_manager.state import importing as app_state_importing
from vpn_manager.state import model as app_state_model
from vpn_manager.xray import rendering as app_xray_rendering


def command_init(args: argparse.Namespace, *, store) -> None:
    if args.state.exists() and not args.force:
        raise app_errors.VpnctlError(
            f"state already exists: {args.state}. Use --force to overwrite it."
        )
    default_domain = args.default_domain or args.server_host
    quota_bytes = app_values.parse_size(args.quota)
    state = app_state_creation.create_state(
        server_host=args.server_host,
        reality_target=args.reality_target,
        default_domain=default_domain,
        port=args.port,
        client_names=args.client,
        quota_bytes=quota_bytes,
        profile_name=args.profile,
        upstream_link=args.upstream_link,
        mode=args.mode,
        direct_port=args.direct_port,
        proxy_port=args.proxy_port,
    )
    store.save(args.state, state)
    app_xray_rendering.render_and_save_config(state, args.config)
    print(f"State saved to {args.state}")
    print(f"Xray config rendered to {args.config}")
    for profile in app_state_model.all_profiles(state):
        for client in profile["clients"]:
            print(
                f"Client {app_state_model.profile_label(profile)}/{client['name']}: {app_exports_links.generate_vless_link(client, state, profile)}"
            )


def command_import_config(args: argparse.Namespace, *, store) -> None:
    if args.state.exists() and not args.force:
        raise app_errors.VpnctlError(
            f"state already exists: {args.state}. Use --force to overwrite it."
        )
    config = app_files.load_json(args.input)
    state = app_state_importing.import_state_from_xray_config(
        config, args.server_host, args.default_domain
    )
    store.save(args.state, state)
    app_xray_rendering.render_and_save_config(state, args.config)
    print(f"Imported Xray config from {args.input}")
    print(f"State saved to {args.state}")
    print(f"Xray config rendered to {args.config}")
    for profile in app_state_model.all_profiles(state):
        print(
            f"Profile {app_state_model.profile_label(profile)}: port={profile['port']} "
            f"outbound={app_state_model.profile_outbound_mode(profile)} clients={len(profile.get('clients', []))}"
        )


def command_render(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    app_accounting.ensure_monthly_period(state)
    persist(state, args.state, args.config)
    print(f"Xray config rendered to {args.config}")
