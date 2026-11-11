"""Adapt runtime CLI operations to their individual workflow dependencies."""

import subprocess
import sys

from vpn_manager.errors import VpnctlError
from vpn_manager.settings import XRAY_SERVICE
from vpn_manager.xray.rendering import render_config


def command_up(args, *, store, deploy):
    state = store.load(args.state)
    deploy(
        state,
        args.state,
        args.config,
        args.compose_file,
        render_config(state),
        force=True,
    )


def command_restart(args, *, store, deploy):
    command_up(args, store=store, deploy=deploy)


def command_down(args, *, store, sample, compose):
    state = store.load(args.state)
    if compose(
        args.compose_file, ["ps", "-q", XRAY_SERVICE], capture=True
    ).stdout.strip():
        try:
            sample(state, args.compose_file)
        except (VpnctlError, OSError, ValueError, subprocess.SubprocessError):
            print(
                "Xray statistics unavailable; stopping may lose unobserved traffic.",
                file=sys.stderr,
            )
        else:
            store.save(args.state, state)
    compose(args.compose_file, ["down"])


def command_status(args, *, compose):
    compose(args.compose_file, ["ps"])


def command_logs(args, *, compose):
    compose(args.compose_file, ["logs", *(["-f"] if args.follow else []), XRAY_SERVICE])


def command_validate(args, *, compose):
    compose(
        args.compose_file,
        [
            "run",
            "--rm",
            XRAY_SERVICE,
            "run",
            "-test",
            "-config",
            "/etc/xray/config.json",
        ],
    )
