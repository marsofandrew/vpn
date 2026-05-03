#!/usr/bin/env python3
import argparse
import sys

import vpnctl


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compatibility wrapper for vpnctl init. Prefer using vpnctl.py directly."
    )
    parser.add_argument("--default-domain", required=True)
    parser.add_argument("--dest", required=True, help="REALITY target, for example www.cloudflare.com:443.")
    parser.add_argument("--server-host", default="127.0.0.1", help="Public host clients connect to.")
    parser.add_argument("--client-names", nargs="+", required=True)
    parser.add_argument("--output-file", default="data/vpn_state.json")
    parser.add_argument("--config-file", default="data/config.json")
    parser.add_argument("--quota")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    argv = [
        "--state",
        args.output_file,
        "--config",
        args.config_file,
        "init",
        "--server-host",
        args.server_host,
        "--reality-target",
        args.dest,
        "--default-domain",
        args.default_domain,
    ]
    for client_name in args.client_names:
        argv.extend(["--client", client_name])
    if args.quota:
        argv.extend(["--quota", args.quota])
    if args.force:
        argv.append("--force")
    return vpnctl.main(argv)


if __name__ == "__main__":
    sys.exit(main())
