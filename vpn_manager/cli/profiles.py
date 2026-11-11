import argparse

from vpn_manager import accounting as app_accounting
from vpn_manager import clock as app_clock
from vpn_manager import errors as app_errors
from vpn_manager import settings as app_settings
from vpn_manager import values as app_values
from vpn_manager.exports import links as app_exports_links
from vpn_manager.state import creation as app_state_creation
from vpn_manager.state import model as app_state_model


def command_profile_list(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    if app_accounting.ensure_monthly_period(state):
        persist(state, args.state, args.config)
    for profile in app_state_model.all_profiles(state):
        clients = profile.get("clients", [])
        enabled_count = sum(1 for client in clients if client.get("enabled", True))
        print(
            f"{app_state_model.profile_label(profile)}\tport={profile['port']}\treality_target={profile['reality_target']}"
            f"\toutbound={app_state_model.profile_outbound_mode(profile)}\tclients={enabled_count}/{len(clients)}"
        )


def command_profile_add(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    app_accounting.ensure_monthly_period(state)
    profile_name = app_values.validate_profile_name(args.name)
    if app_state_model.find_profile(state, profile_name):
        raise app_errors.VpnctlError(f"profile already exists: {profile_name}")
    quota_bytes = app_values.parse_size(args.quota)
    outbound_mode = args.outbound or app_settings.OUTBOUND_DIRECT
    profile = app_state_creation.create_profile(
        profile_name,
        args.reality_target,
        state["default_domain"],
        args.port,
        args.client or [],
        quota_bytes,
        outbound_mode,
    )
    _configure_transport(profile, args)
    state["profiles"].append(profile)
    persist(
        state, args.state, args.config, args.compose_file, restart=not args.no_restart
    )
    print(
        f"Profile added: {app_state_model.profile_label(profile)} on port {profile['port']} outbound={app_state_model.profile_outbound_mode(profile)}"
    )
    for client in profile["clients"]:
        print(
            f"Client {app_state_model.profile_label(profile)}/{client['name']}: {app_exports_links.generate_vless_link(client, state, profile)}"
        )


def _configure_transport(profile, args):
    if args.transport == "xhttp":
        profile["transport"] = {
            "type": "xhttp",
            "settings": {
                "path": args.path,
                "host": args.host or "",
                "mode": args.xhttp_mode
                or ("stream-one" if args.security == "reality" else "auto"),
            },
        }
    _configure_security(profile, args)


def _configure_security(profile, args):
    if args.security == "tls":
        if (
            args.transport != "xhttp"
            or not args.certificate
            or not args.certificate_key
            or not args.tls_server_name
        ):
            raise app_errors.VpnctlError(
                "XHTTP TLS requires certificate, certificate-key and tls-server-name"
            )
        profile["security"] = {
            "type": "tls",
            "settings": {
                "server_name": args.tls_server_name,
                "certificates": [
                    {
                        "certificateFile": args.certificate,
                        "keyFile": args.certificate_key,
                    }
                ],
            },
        }
        _apply_ech_files(profile, args)
    elif args.ech_server_keys_file:
        raise app_errors.VpnctlError("ECH server keys require TLS security")


def _apply_ech_files(profile, args):
    if args.ech_server_keys_file:
        if not args.ech_config_list_file:
            raise app_errors.VpnctlError(
                "ECH profiles require both server keys and public client config files"
            )
        profile["security"]["settings"]["ech_server_keys"] = (
            args.ech_server_keys_file.read_text(encoding="utf-8").strip()
        )
        profile["client_ech_config_list"] = args.ech_config_list_file.read_text(
            encoding="utf-8"
        ).strip()


def command_profile_remove(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    app_accounting.ensure_monthly_period(state)
    profile = app_state_model.require_profile(state, args.name)
    if len(app_state_model.all_profiles(state)) == 1:
        raise app_errors.VpnctlError("cannot remove the last profile")
    state["profiles"] = [
        item
        for item in app_state_model.all_profiles(state)
        if app_state_model.profile_label(item) != app_state_model.profile_label(profile)
    ]
    persist(
        state, args.state, args.config, args.compose_file, restart=not args.no_restart
    )
    print(f"Profile removed: {app_state_model.profile_label(profile)}")


def command_profile_outbound(args: argparse.Namespace, *, persist, store) -> None:
    state = store.load(args.state)
    app_accounting.ensure_monthly_period(state)
    profile = app_state_model.require_profile(state, args.name)
    profile["outbound_mode"] = app_values.validate_outbound_mode(args.outbound)
    profile["route"] = (
        "direct" if args.outbound == "direct" else app_settings.UPSTREAM_OUTBOUND_TAG
    )
    profile["updated_at"] = app_clock.utc_now()
    persist(
        state, args.state, args.config, args.compose_file, restart=not args.no_restart
    )
    print(
        f"Profile outbound updated: {app_state_model.profile_label(profile)} outbound={app_state_model.profile_outbound_mode(profile)}"
    )
