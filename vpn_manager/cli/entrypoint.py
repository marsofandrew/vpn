import json
import os
import subprocess
import sys

from vpn_manager import errors as app_errors
from vpn_manager.cli import parser as app_cli_parser
from vpn_manager.state import storage as app_state_storage
from vpn_manager.xray import deployment as app_xray_deployment


def main(argv: list[str] | None = None) -> int:
    parser = app_cli_parser.build_parser()
    args = parser.parse_args(argv)
    args.state = args.state.resolve()
    args.config = args.config.resolve()
    args.compose_file = args.compose_file.resolve()
    try:
        os.environ["XRAY_CONFIG_PATH"] = str(args.config.resolve())
        if args.command in {"logs", "status"} or (
            args.command == "inventory" and not getattr(args, "with_runtime", False)
        ):
            args.func(args)
        else:
            with app_state_storage.state_lock(args.state):
                if app_xray_deployment.journal_path(args.state).exists():
                    app_xray_deployment.recover_deployment(
                        args.state, args.config, args.compose_file
                    )
                args.func(args)
    except (
        app_errors.VpnctlError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
        OSError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0
