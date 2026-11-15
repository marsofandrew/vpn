import argparse
from pathlib import Path

from vpn_manager import settings as app_settings
from vpn_manager import values as app_values
from vpn_manager.cli import clients as app_cli_clients
from vpn_manager.cli import exports as app_cli_exports
from vpn_manager.cli import health as app_cli_health
from vpn_manager.cli import initialization as app_cli_initialization
from vpn_manager.cli import inventory as app_cli_inventory
from vpn_manager.cli import profiles as app_cli_profiles
from vpn_manager.cli import routing as app_cli_routing
from vpn_manager.cli import runtime as app_cli_runtime
from vpn_manager.cli import usage as app_cli_usage


def add_common_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--state",
        type=Path,
        default=app_settings.DEFAULT_STATE_PATH,
        help="Path to vpnctl state JSON.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=app_settings.DEFAULT_CONFIG_PATH,
        help="Path to rendered Xray config JSON.",
    )
    parser.add_argument(
        "--compose-file",
        type=Path,
        default=app_settings.DEFAULT_COMPOSE_FILE,
        help="Path to Docker Compose file.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage a Docker Compose Xray VLESS + REALITY VPN server."
    )
    add_common_paths(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)
    register_init(subparsers)
    register_import_config(subparsers)
    register_render(subparsers)
    register_upstream(subparsers)
    register_route(subparsers)
    register_policy(subparsers)
    register_node(subparsers)
    register_health(subparsers)
    register_profile(subparsers)
    register_client(subparsers)
    register_quota(subparsers)
    register_usage(subparsers)
    register_link(subparsers)
    register_endpoint(subparsers)
    register_subscription(subparsers)
    register_inventory(subparsers)
    register_up(subparsers)
    register_down(subparsers)
    register_restart(subparsers)
    register_status(subparsers)
    register_logs(subparsers)
    register_validate(subparsers)
    return parser


def register_init(subparsers):
    init_parser = subparsers.add_parser(
        "init", help="Create state and render the initial Xray config."
    )
    init_parser.add_argument(
        "--server-host", required=True, help="Public IP or DNS name clients connect to."
    )
    init_parser.add_argument(
        "--upstream-link", help="VLESS + REALITY client link for an upstream VPN."
    )
    init_parser.add_argument(
        "--reality-target",
        required=True,
        help="REALITY target, for example www.cloudflare.com:443.",
    )
    init_parser.add_argument(
        "--default-domain",
        help="Domain used in generated client emails. Defaults to server host.",
    )
    _add_init_profiles(init_parser)
    _add_init_clients(init_parser)
    init_parser.set_defaults(func=app_cli_initialization.command_init)


def _add_init_profiles(init_parser):
    init_parser.add_argument(
        "--mode",
        choices=["direct", "proxy", "both"],
        default=app_settings.OUTBOUND_DIRECT,
        help="Initial outbound profile mode.",
    )
    init_parser.add_argument(
        "--port",
        type=app_values.parse_port,
        help="Public VLESS port for direct-only or proxy-only init. Defaults to 443.",
    )
    init_parser.add_argument(
        "--direct-port",
        type=app_values.parse_port,
        default=app_settings.DEFAULT_PORT,
        help="Public VLESS port for the direct profile in both mode.",
    )
    init_parser.add_argument(
        "--proxy-port",
        type=app_values.parse_port,
        default=8443,
        help="Public VLESS port for the proxy profile in both mode.",
    )
    init_parser.add_argument(
        "--profile",
        default=app_settings.DEFAULT_PROFILE_NAME,
        help="Initial profile name for direct-only or proxy-only init.",
    )


def _add_init_clients(init_parser):
    init_parser.add_argument(
        "--client",
        action="append",
        required=True,
        help="Initial client name. Repeatable.",
    )
    init_parser.add_argument(
        "--quota",
        help="Optional initial monthly quota for all created clients, for example 50GiB.",
    )
    init_parser.add_argument(
        "--force", action="store_true", help="Overwrite existing state."
    )


def register_import_config(subparsers):
    import_parser = subparsers.add_parser(
        "import-config", help="Import an existing Xray JSON config into vpnctl state."
    )
    import_parser.add_argument(
        "--input", type=Path, required=True, help="Existing Xray config JSON to import."
    )
    import_parser.add_argument(
        "--server-host", required=True, help="Public IP or DNS name clients connect to."
    )
    import_parser.add_argument(
        "--default-domain",
        help="Domain used in imported client emails. Defaults to inferred email domain or server host.",
    )
    import_parser.add_argument(
        "--force", action="store_true", help="Overwrite existing state."
    )
    import_parser.set_defaults(func=app_cli_initialization.command_import_config)


def register_render(subparsers):
    render_parser = subparsers.add_parser("render", help="Render config from state.")
    render_parser.set_defaults(func=app_cli_initialization.command_render)


def register_upstream(subparsers):
    upstream_parser = subparsers.add_parser(
        "upstream", help="Show or change the upstream VPN."
    )
    upstream_subparsers = upstream_parser.add_subparsers(
        dest="upstream_command", required=True
    )
    _register_upstream_show(upstream_subparsers)
    _register_upstream_set(upstream_subparsers)
    _register_upstream_clear(upstream_subparsers)
    _register_upstream_list(upstream_subparsers)
    _register_upstream_bind(upstream_subparsers)


def _register_upstream_show(upstream_subparsers):
    upstream_show_parser = upstream_subparsers.add_parser(
        "show", help="Show the configured upstream without printing UUIDs."
    )
    upstream_show_parser.add_argument(
        "name", nargs="?", default=app_settings.UPSTREAM_OUTBOUND_TAG
    )
    upstream_show_parser.set_defaults(func=app_cli_routing.command_upstream_show)


def _register_upstream_set(upstream_subparsers):
    upstream_set_parser = upstream_subparsers.add_parser(
        "set", help="Replace the upstream VPN link."
    )
    upstream_set_parser.add_argument(
        "--link", required=True, help="VLESS + REALITY client link for an upstream VPN."
    )
    upstream_set_parser.add_argument("--no-restart", action="store_true")
    upstream_set_parser.set_defaults(func=app_cli_routing.command_upstream_set)


def _register_upstream_clear(upstream_subparsers):
    upstream_clear_parser = upstream_subparsers.add_parser(
        "clear", help="Clear upstream when no proxy profiles exist."
    )
    upstream_clear_parser.add_argument("--no-restart", action="store_true")
    upstream_clear_parser.set_defaults(func=app_cli_routing.command_upstream_clear)


def _register_upstream_list(upstream_subparsers):
    upstream_list_parser = upstream_subparsers.add_parser(
        "list", help="List named upstreams."
    )
    upstream_list_parser.set_defaults(func=app_cli_routing.command_upstream_list)


def _register_upstream_bind(upstream_subparsers):
    upstream_bind = upstream_subparsers.add_parser(
        "bind", help="Associate an upstream with inventory metadata."
    )
    upstream_bind.add_argument("name")
    upstream_bind.add_argument("--node", required=True)
    upstream_bind.add_argument("--inventory", type=Path, required=True)
    upstream_bind.set_defaults(func=app_cli_inventory.command_upstream_bind)
    for operation in ("add", "remove", "enable", "disable"):
        operation_parser = upstream_subparsers.add_parser(operation)
        operation_parser.add_argument("name")
        operation_parser.add_argument("--no-restart", action="store_true")
        if operation == "add":
            operation_parser.add_argument("--link", required=True)
            operation_parser.set_defaults(func=app_cli_routing.command_upstream_set)
        elif operation == "remove":
            operation_parser.set_defaults(func=app_cli_routing.command_upstream_clear)
        else:
            operation_parser.set_defaults(func=app_cli_routing.command_upstream_enabled)


def register_route(subparsers):
    route_parser = subparsers.add_parser(
        "route", help="Assign profile routing policies."
    )
    route_subparsers = route_parser.add_subparsers(dest="route_command", required=True)
    for operation in ("show", "set"):
        operation_parser = route_subparsers.add_parser(operation)
        operation_parser.add_argument("profile")
        if operation == "set":
            operation_parser.add_argument("--policy", required=True)
            operation_parser.add_argument("--no-restart", action="store_true")
        operation_parser.set_defaults(func=app_cli_routing.command_route)


def register_policy(subparsers):
    policy_parser = subparsers.add_parser(
        "policy", help="Manage named routing policies."
    )
    policy_subparsers = policy_parser.add_subparsers(
        dest="policy_command", required=True
    )
    policy_subparsers.add_parser("list").set_defaults(
        func=app_cli_routing.command_policy
    )
    policy_set = policy_subparsers.add_parser("set")
    policy_set.add_argument("name")
    policy_set.add_argument(
        "--type",
        choices=["direct", "block", "upstream", "balanced", "priority"],
        required=True,
    )
    policy_set.add_argument("--upstream", action="append")
    policy_set.add_argument("--cooldown", type=float, default=60)
    policy_set.add_argument("--no-restart", action="store_true")
    policy_set.set_defaults(func=app_cli_routing.command_policy)


def register_node(subparsers):
    node_parser = subparsers.add_parser(
        "node", help="Configure local node role and routing guard."
    )
    node_parser.add_argument("--id", required=True)
    node_parser.add_argument(
        "--role", choices=["gateway", "exit", "both"], required=True
    )
    node_parser.add_argument("--foreign-only", action="store_true")
    node_parser.add_argument("--no-restart", action="store_true")
    node_parser.set_defaults(func=app_cli_routing.command_node)


def register_health(subparsers):
    health_parser = subparsers.add_parser(
        "health", help="Inspect or probe upstream paths on this gateway."
    )
    health_parser.set_defaults(
        func=app_cli_health.command_health, health_command="show"
    )
    health_subparsers = health_parser.add_subparsers(dest="health_command")
    health_subparsers.add_parser("events").set_defaults(
        func=app_cli_health.command_health
    )
    health_check = health_subparsers.add_parser("check")
    health_check.add_argument("--no-restart", action="store_true")
    health_check.set_defaults(func=app_cli_health.command_health)
    health_configure = health_subparsers.add_parser("configure")
    health_configure.add_argument("name")
    health_configure.add_argument("--download-url", required=True)
    health_configure.add_argument("--egress-url", required=True)
    health_configure.add_argument("--expected-exit-ip", action="append", required=True)
    health_configure.add_argument("--interval", type=float, default=30)
    health_configure.add_argument("--fail-threshold", type=int, default=3)
    health_configure.add_argument("--success-threshold", type=int, default=3)
    health_configure.add_argument("--timeout", type=float, default=15)
    health_configure.add_argument(
        "--bytes-required", type=int, choices=[131072, 1048576], default=131072
    )
    health_configure.set_defaults(func=app_cli_health.command_health)


def register_profile(subparsers):
    profile_parser = subparsers.add_parser("profile", help="Manage VPN profiles.")
    profile_subparsers = profile_parser.add_subparsers(
        dest="profile_command", required=True
    )
    _register_profile_list(profile_subparsers)
    _register_profile_add(profile_subparsers)
    _register_profile_remove(profile_subparsers)
    _register_profile_outbound(profile_subparsers)


def _register_profile_list(profile_subparsers):
    profile_list_parser = profile_subparsers.add_parser(
        "list", help="List VPN profiles."
    )
    profile_list_parser.set_defaults(func=app_cli_profiles.command_profile_list)


def _register_profile_add(profile_subparsers):
    profile_add_parser = profile_subparsers.add_parser(
        "add", help="Add a VPN profile on another port."
    )
    profile_add_parser.add_argument("name")
    profile_add_parser.add_argument(
        "--port",
        type=app_values.parse_port,
        required=True,
        help="Public VLESS port for this profile.",
    )
    profile_add_parser.add_argument(
        "--outbound",
        choices=["direct", "proxy"],
        help="Outbound route for this profile.",
    )
    profile_add_parser.add_argument(
        "--reality-target", default="www.cloudflare.com:443", help="REALITY target."
    )
    profile_add_parser.add_argument(
        "--transport", choices=["tcp", "xhttp"], default="tcp"
    )
    profile_add_parser.add_argument(
        "--security", choices=["reality", "tls"], default="reality"
    )
    profile_add_parser.add_argument("--path", default="/")
    profile_add_parser.add_argument("--host")
    profile_add_parser.add_argument(
        "--xhttp-mode", choices=["auto", "packet-up", "stream-up", "stream-one"]
    )
    profile_add_parser.add_argument("--tls-server-name")
    profile_add_parser.add_argument("--certificate")
    profile_add_parser.add_argument("--certificate-key")
    profile_add_parser.add_argument("--ech-server-keys-file", type=Path)
    profile_add_parser.add_argument("--ech-config-list-file", type=Path)
    profile_add_parser.add_argument(
        "--client", action="append", help="Initial client name. Repeatable."
    )
    profile_add_parser.add_argument(
        "--quota",
        help="Optional initial monthly quota for created clients, for example 50GiB.",
    )
    profile_add_parser.add_argument("--no-restart", action="store_true")
    profile_add_parser.set_defaults(func=app_cli_profiles.command_profile_add)


def _register_profile_remove(profile_subparsers):
    profile_remove_parser = profile_subparsers.add_parser(
        "remove", help="Remove a VPN profile and its clients."
    )
    profile_remove_parser.add_argument("name")
    profile_remove_parser.add_argument("--no-restart", action="store_true")
    profile_remove_parser.set_defaults(func=app_cli_profiles.command_profile_remove)


def _register_profile_outbound(profile_subparsers):
    profile_outbound_parser = profile_subparsers.add_parser(
        "outbound", help="Change a profile outbound route."
    )
    profile_outbound_parser.add_argument("name")
    profile_outbound_parser.add_argument(
        "--outbound", choices=["direct", "proxy"], required=True
    )
    profile_outbound_parser.add_argument("--no-restart", action="store_true")
    profile_outbound_parser.set_defaults(func=app_cli_profiles.command_profile_outbound)


def register_client(subparsers):
    client_parser = subparsers.add_parser("client", help="Manage clients.")
    client_subparsers = client_parser.add_subparsers(
        dest="client_command", required=True
    )
    _register_client_add(client_subparsers)
    _register_client_remove(client_subparsers)
    _register_client_list(client_subparsers)
    _register_client_enable(client_subparsers)
    _register_client_disable(client_subparsers)


def _register_client_add(client_subparsers):
    add_parser = client_subparsers.add_parser("add", help="Add a client.")
    add_parser.add_argument("name")
    add_parser.add_argument(
        "--profile",
        default=app_settings.DEFAULT_PROFILE_NAME,
        help="VPN profile to add the client to.",
    )
    add_parser.add_argument(
        "--quota", help="Optional monthly quota, for example 50GiB."
    )
    add_parser.add_argument("--no-restart", action="store_true")
    add_parser.set_defaults(func=app_cli_clients.command_client_add)


def _register_client_remove(client_subparsers):
    remove_parser = client_subparsers.add_parser("remove", help="Remove a client.")
    remove_parser.add_argument("name_or_id")
    remove_parser.add_argument(
        "--profile", help="VPN profile to remove the client from."
    )
    remove_parser.add_argument("--no-restart", action="store_true")
    remove_parser.set_defaults(func=app_cli_clients.command_client_remove)


def _register_client_list(client_subparsers):
    list_parser = client_subparsers.add_parser("list", help="List clients.")
    list_parser.add_argument("--profile", help="Only list clients in this VPN profile.")
    list_parser.set_defaults(func=app_cli_clients.command_client_list)


def _register_client_enable(client_subparsers):
    enable_parser = client_subparsers.add_parser("enable", help="Enable a client.")
    enable_parser.add_argument("name_or_id")
    enable_parser.add_argument("--profile", help="VPN profile containing the client.")
    enable_parser.add_argument("--no-restart", action="store_true")
    enable_parser.set_defaults(func=app_cli_clients.command_client_enable)


def _register_client_disable(client_subparsers):
    disable_parser = client_subparsers.add_parser("disable", help="Disable a client.")
    disable_parser.add_argument("name_or_id")
    disable_parser.add_argument("--profile", help="VPN profile containing the client.")
    disable_parser.add_argument("--reason", default="manual")
    disable_parser.add_argument("--no-restart", action="store_true")
    disable_parser.set_defaults(func=app_cli_clients.command_client_disable)


def register_quota(subparsers):
    quota_parser = subparsers.add_parser("quota", help="Manage monthly traffic quotas.")
    quota_subparsers = quota_parser.add_subparsers(dest="quota_command", required=True)
    _register_quota_set(quota_subparsers)
    _register_quota_reset(quota_subparsers)
    _register_quota_enforce(quota_subparsers)


def _register_quota_set(quota_subparsers):
    quota_set_parser = quota_subparsers.add_parser(
        "set", help="Set a client monthly quota."
    )
    quota_set_parser.add_argument("name_or_id")
    quota_set_parser.add_argument(
        "--profile", help="VPN profile containing the client."
    )
    quota_set_parser.add_argument("--quota", required=True)
    quota_set_parser.set_defaults(func=app_cli_usage.command_quota_set)


def _register_quota_reset(quota_subparsers):
    quota_reset_parser = quota_subparsers.add_parser(
        "reset", help="Reset usage counters for a client."
    )
    quota_reset_parser.add_argument("name_or_id")
    quota_reset_parser.add_argument(
        "--profile", help="VPN profile containing the client."
    )
    quota_reset_parser.add_argument(
        "--enable", action="store_true", help="Enable the client after resetting usage."
    )
    quota_reset_parser.add_argument("--no-restart", action="store_true")
    quota_reset_parser.set_defaults(func=app_cli_usage.command_quota_reset)


def _register_quota_enforce(quota_subparsers):
    quota_enforce_parser = quota_subparsers.add_parser(
        "enforce", help="Pull Xray stats and disable clients over monthly quota."
    )
    quota_enforce_parser.add_argument("--no-restart", action="store_true")
    quota_enforce_parser.set_defaults(func=app_cli_usage.command_quota_enforce)


def register_usage(subparsers):
    usage_parser = subparsers.add_parser("usage", help="Show persisted usage.")
    usage_parser.add_argument("--profile", help="Only show usage for this VPN profile.")
    usage_parser.add_argument(
        "--refresh",
        action="store_true",
        help="Read current Xray counters before printing.",
    )
    usage_parser.set_defaults(func=app_cli_usage.command_usage)


def register_link(subparsers):
    link_parser = subparsers.add_parser("link", help="Print a VLESS link for a client.")
    link_parser.add_argument("name_or_id")
    link_parser.add_argument("--profile", help="VPN profile containing the client.")
    link_parser.add_argument(
        "--fingerprint",
        "--fp",
        help="Override the REALITY client fingerprint for this export, for example safari or firefox.",
    )
    link_parser.add_argument("--qr", action="store_true", help="Write a QR code PNG.")
    link_parser.add_argument(
        "--output", type=Path, default=Path("qrcodes"), help="QR output directory."
    )
    link_parser.set_defaults(func=app_cli_clients.command_link)


def register_endpoint(subparsers):
    endpoint_parser = subparsers.add_parser(
        "endpoint", help="Manage independent remote client entries."
    )
    endpoint_subparsers = endpoint_parser.add_subparsers(
        dest="endpoint_command", required=True
    )
    endpoint_subparsers.add_parser("list").set_defaults(
        func=app_cli_exports.command_endpoint
    )
    endpoint_add = endpoint_subparsers.add_parser("add")
    endpoint_add.add_argument("name")
    endpoint_add.add_argument("--client", required=True)
    endpoint_add.add_argument("--link", required=True)
    endpoint_add.set_defaults(func=app_cli_exports.command_endpoint)
    endpoint_remove = endpoint_subparsers.add_parser("remove")
    endpoint_remove.add_argument("name")
    endpoint_remove.set_defaults(func=app_cli_exports.command_endpoint)


def register_subscription(subparsers):
    subscription_parser = subparsers.add_parser(
        "subscription", help="Export a private combined subscription file."
    )
    subscription_parser.add_argument("client")
    subscription_parser.add_argument("--output", type=Path, required=True)
    subscription_parser.set_defaults(func=app_cli_exports.command_subscription)


def register_inventory(subparsers):
    inventory_parser = subparsers.add_parser(
        "inventory", help="Manage separate infrastructure metadata."
    )
    inventory_subparsers = inventory_parser.add_subparsers(
        dest="inventory_command", required=True
    )
    for operation in ("example", "validate", "list"):
        operation_parser = inventory_subparsers.add_parser(operation)
        operation_parser.add_argument(
            "--file", type=Path, default=Path("data/inventory.json")
        )
        if operation == "validate":
            operation_parser.add_argument("--with-runtime", action="store_true")
        operation_parser.set_defaults(func=app_cli_inventory.command_inventory)


def register_up(subparsers):
    up_parser = subparsers.add_parser("up", help="Start Xray.")
    up_parser.set_defaults(func=app_cli_runtime.command_up)


def register_down(subparsers):
    down_parser = subparsers.add_parser("down", help="Stop Xray.")
    down_parser.set_defaults(func=app_cli_runtime.command_down)


def register_restart(subparsers):
    restart_parser = subparsers.add_parser("restart", help="Restart Xray.")
    restart_parser.set_defaults(func=app_cli_runtime.command_restart)


def register_status(subparsers):
    status_parser = subparsers.add_parser("status", help="Show Compose service status.")
    status_parser.set_defaults(func=app_cli_runtime.command_status)


def register_logs(subparsers):
    logs_parser = subparsers.add_parser("logs", help="Follow Xray logs.")
    logs_parser.add_argument("-f", "--follow", action="store_true")
    logs_parser.set_defaults(func=app_cli_runtime.command_logs)


def register_validate(subparsers):
    validate_parser = subparsers.add_parser(
        "validate", help="Validate the rendered Xray config inside the container."
    )
    validate_parser.set_defaults(func=app_cli_runtime.command_validate)
