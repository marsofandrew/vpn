#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

import vpnctl


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compatibility wrapper for vpnctl client/link commands. Prefer using vpnctl.py directly."
    )
    parser.add_argument("--config", default="data/vpn_state.json", help="Path to vpnctl state JSON.")
    parser.add_argument("--server-config", default="data/config.json", help="Path to rendered Xray config JSON.")
    parser.add_argument("--add-client")
    parser.add_argument("--remove-client")
    parser.add_argument("--get-link")
    parser.add_argument("--qr", action="store_true")
    parser.add_argument("--qr-folder", default="qrcodes")
    parser.add_argument("--server-ip", help="Deprecated. Set server_host during vpnctl init instead.")
    parser.add_argument("--quota")
    parser.add_argument("--no-restart", action="store_true")
    args = parser.parse_args()

    common = ["--state", args.config, "--config", args.server_config]
    if args.add_client:
        argv = [*common, "client", "add", args.add_client]
        if args.quota:
            argv.extend(["--quota", args.quota])
        if args.no_restart:
            argv.append("--no-restart")
        return vpnctl.main(argv)
    if args.remove_client:
        argv = [*common, "client", "remove", args.remove_client]
        if args.no_restart:
            argv.append("--no-restart")
        return vpnctl.main(argv)
    if args.get_link:
        if args.server_ip:
            state = vpnctl.load_state(Path(args.config))
            state["server_host"] = args.server_ip
            client = vpnctl.require_client(state, args.get_link)
            link = vpnctl.generate_vless_link(client, state)
            print(link)
            if args.qr:
                path = vpnctl.write_qr(link, client["name"], Path(args.qr_folder))
                print(f"QR code saved to {path}")
            return 0
        argv = [*common, "link", args.get_link]
        if args.qr:
            argv.extend(["--qr", "--output", str(Path(args.qr_folder))])
        return vpnctl.main(argv)

    parser.error("provide one of --add-client, --remove-client, or --get-link")
    return 2


if __name__ == "__main__":
    sys.exit(main())
