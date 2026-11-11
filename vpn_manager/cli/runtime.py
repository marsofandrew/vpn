import argparse
import subprocess
import sys

from vpn_manager import accounting as app_accounting
from vpn_manager import errors as app_errors
from vpn_manager import settings as app_settings
from vpn_manager.state import storage as app_state_storage
from vpn_manager.xray import deployment as app_xray_deployment
from vpn_manager.xray import rendering as app_xray_rendering
from vpn_manager.xray import runtime as app_xray_runtime


def command_compose(args: argparse.Namespace, compose_args: list[str]) -> None:
    if compose_args[0] in {"up", "restart"}:
        state = app_state_storage.load_state(args.state)
        app_xray_deployment.deploy_config(
            state,
            args.state,
            args.config,
            args.compose_file,
            app_xray_rendering.render_config(state),
            force=True,
        )
    elif compose_args[0] == "down":
        state = app_state_storage.load_state(args.state)
        if app_xray_runtime.run_compose(
            args.compose_file, ["ps", "-q", app_settings.XRAY_SERVICE], capture=True
        ).stdout.strip():
            try:
                app_accounting.sample_usage(state, args.compose_file)
            except (
                app_errors.VpnctlError,
                OSError,
                ValueError,
                subprocess.SubprocessError,
            ):
                print(
                    "Xray statistics unavailable; stopping may lose unobserved traffic.",
                    file=sys.stderr,
                )
            else:
                app_state_storage.save_state(args.state, state)
        app_xray_runtime.run_compose(args.compose_file, compose_args)
    else:
        app_xray_runtime.run_compose(args.compose_file, compose_args)
