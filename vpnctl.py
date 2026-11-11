#!/usr/bin/env python3
"""Executable entry point for the VPN manager."""

from vpn_manager.cli.entrypoint import main
from vpn_manager.errors import VpnctlError

__all__ = ["main", "VpnctlError"]


if __name__ == "__main__":
    raise SystemExit(main())
