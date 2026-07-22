# Xray VLESS + REALITY VPN Setup

Provision and manage a Docker Compose based Xray VPN server using VLESS + REALITY.

The repo includes:

- `vpnctl.py`: one CLI for setup, runtime control, VPN profiles, clients, links, QR codes, usage, and monthly quotas
- `docker-compose.yaml`: Xray runtime using the official `ghcr.io/xtls/xray-core` image with host networking so Xray can bind every configured profile port
- `scripts/install-host.sh`: Ubuntu/Debian host bootstrap with Docker's official apt repository, firewall, and quota timer setup

Generated secrets and runtime config live under `data/` and are ignored by git.

## Quick Start

Run these commands on a fresh Ubuntu/Debian VPS.

```bash
git clone <this-repo-url>
cd vpn-setup
./scripts/install-host.sh
```

Initialize the server state and create initial clients:

```bash
python3 vpnctl.py init \
  --server-host YOUR_SERVER_IP_OR_DOMAIN \
  --port 8443 \
  --reality-target www.cloudflare.com:443 \
  --default-domain vpn.local \
  --client phone \
  --client laptop \
  --quota 50GiB
```

`init` creates the first direct VPN profile, named `default` unless you pass `--profile NAME`. `--port` controls that profile's public VPN TCP port and Xray inbound port. Omit it to use `443`. If you use a custom port such as `8443`, open that TCP port in `ufw` and in your cloud firewall. `--quota 50GiB` means 50 GiB per calendar month. Usage periods reset on the first day of each UTC month.

Start and validate Xray:

```bash
python3 vpnctl.py up
python3 vpnctl.py validate
python3 vpnctl.py status
```

Print a client link or QR code:

```bash
python3 vpnctl.py link phone
python3 vpnctl.py link phone --qr
```

## Requirements

On the server:

- Ubuntu or Debian
- root or sudo access
- one or more configured public TCP ports reachable from clients, default `443`
- Docker Compose plugin, installed from Docker's official apt repository by `scripts/install-host.sh` if missing

For local development without running the host installer:

```bash
python3 -m pip install -r requirements.txt
```

## Important Files

- `data/vpn_state.json`: source of truth for upstream settings, profiles, outbound routes, ports, private keys, REALITY short IDs, clients, monthly quotas, usage period, and usage
- `data/config.json`: rendered Xray config mounted into the container
- `qrcodes/`: generated QR code PNG files
- `.env`: optional Docker Compose overrides such as `XRAY_IMAGE` or `XRAY_CONTAINER_NAME`

Do not commit `data/`, `.env`, QR codes, or any generated state. Losing `data/vpn_state.json` means losing the private keys, profile settings, and client registry for that server.

## Server Commands

```bash
python3 vpnctl.py up
python3 vpnctl.py down
python3 vpnctl.py restart
python3 vpnctl.py status
python3 vpnctl.py logs -f
python3 vpnctl.py validate
```

If you edit or migrate state manually, re-render the Xray config:

```bash
python3 vpnctl.py render
python3 vpnctl.py restart
```

## Outbound Modes

Each profile has an outbound route:

- `direct`: exits to the internet from this VPS. This is the default and preserves the original behavior.
- `proxy`: routes through a configured upstream VLESS + REALITY VPN link.

Create a proxy-only server:

```bash
python3 vpnctl.py init \
  --server-host YOUR_SERVER_IP_OR_DOMAIN \
  --mode proxy \
  --upstream-link 'VLESS_LINK_FROM_UPSTREAM_VPN' \
  --reality-target www.cloudflare.com:443 \
  --client phone
```

Create direct and proxy profiles together:

```bash
python3 vpnctl.py init \
  --server-host YOUR_SERVER_IP_OR_DOMAIN \
  --mode both \
  --upstream-link 'VLESS_LINK_FROM_UPSTREAM_VPN' \
  --reality-target www.cloudflare.com:443 \
  --client phone
```

By default, `--mode both` creates `direct` on TCP `443` and `proxy` on TCP `8443`.
Use `--direct-port` and `--proxy-port` to change those ports.

Manage the upstream link:

```bash
python3 vpnctl.py upstream show
python3 vpnctl.py upstream set --link 'NEW_VLESS_LINK_FROM_UPSTREAM_VPN'
python3 vpnctl.py upstream clear
```

`upstream clear` is allowed only when no profiles use `outbound=proxy`.

## Import Existing Xray Config

Import an existing Xray JSON config into `vpnctl` state:

```bash
python3 vpnctl.py import-config \
  --input /path/to/config.json \
  --server-host YOUR_SERVER_IP_OR_DOMAIN
```

The config must contain VLESS + REALITY inbounds. If it has a VLESS + REALITY outbound used by routing rules, imported profiles using that route become `proxy`; other profiles become `direct`. Imported quotas are unlimited and usage counters start at zero. Pass `--default-domain DOMAIN` if imported client emails do not share one domain.

## VPN Profiles

A VPN profile is one VLESS + REALITY inbound. Each profile has its own public port, REALITY target, outbound route, private/public keypair, short ID, and client list. The rendered Xray config contains one inbound per profile.

List profiles:

```bash
python3 vpnctl.py profile list
```

Add another profile on a new port:

```bash
python3 vpnctl.py profile add backup \
  --port 8443 \
  --outbound direct \
  --reality-target www.microsoft.com:443 \
  --client tablet \
  --quota 20GiB
```

Add a profile that proxies through the upstream VPN:

```bash
python3 vpnctl.py profile add upstream-exit \
  --port 9443 \
  --outbound proxy \
  --reality-target www.cloudflare.com:443 \
  --client tablet
```

Change an existing profile's outbound route:

```bash
python3 vpnctl.py profile outbound backup --outbound proxy
python3 vpnctl.py profile outbound backup --outbound direct
```

Remove a profile and all clients assigned to it:

```bash
python3 vpnctl.py profile remove backup
```

Profile ports must be unique and cannot use the local Xray API port `10085`. After adding a profile, open its TCP port in `ufw` and in your cloud firewall.

## Client Management

List clients:

```bash
python3 vpnctl.py client list
python3 vpnctl.py client list --profile backup
```

Add a client to the default profile:

```bash
python3 vpnctl.py client add tablet --quota 20GiB
```

Add a client to a specific profile:

```bash
python3 vpnctl.py client add travel-phone --profile backup --quota 20GiB
```

Remove a client:

```bash
python3 vpnctl.py client remove tablet
python3 vpnctl.py client remove travel-phone --profile backup
```

Disable or re-enable a client:

```bash
python3 vpnctl.py client disable phone --reason manual
python3 vpnctl.py client enable phone
python3 vpnctl.py client disable travel-phone --profile backup --reason manual
python3 vpnctl.py client enable travel-phone --profile backup
```

Get a connection link:

```bash
python3 vpnctl.py link phone
python3 vpnctl.py link travel-phone --profile backup
```

Generate a QR code:

```bash
python3 vpnctl.py link phone --qr --output qrcodes
python3 vpnctl.py link travel-phone --profile backup --qr --output qrcodes
```

If the same client name exists in more than one profile, pass `--profile` for remove, enable, disable, quota, usage, and link commands.

## Monthly Traffic Quotas

Quotas are monthly calendar quotas. The active period is stored as `YYYY-MM` in UTC. When the first quota/list/usage command runs in a new UTC month, usage counters reset to zero and clients disabled only for `quota_exceeded` are enabled again.

Quotas are enforced by periodically reading Xray user stats, persisting the traffic totals for the active month, and removing over-quota clients from the rendered Xray config.

Set or change a monthly quota:

```bash
python3 vpnctl.py quota set phone --quota 100GiB
python3 vpnctl.py quota set travel-phone --profile backup --quota 100GiB
```

Show persisted monthly usage:

```bash
python3 vpnctl.py usage
python3 vpnctl.py usage --profile backup
```

Read current Xray counters before showing monthly usage:

```bash
python3 vpnctl.py usage --refresh
python3 vpnctl.py usage --profile backup --refresh
```

Manually enforce quotas:

```bash
python3 vpnctl.py quota enforce
```

Reset monthly usage and re-enable a client:

```bash
python3 vpnctl.py quota reset phone --enable
python3 vpnctl.py quota reset travel-phone --profile backup --enable
```

The host installer creates `vpnctl-quota.timer`, which runs quota enforcement every 5 minutes.

Useful systemd commands:

```bash
systemctl status vpnctl-quota.timer
journalctl -u vpnctl-quota.service -n 100 --no-pager
```

## Troubleshooting

If the container does not start, validate the generated config:

```bash
python3 vpnctl.py validate
python3 vpnctl.py logs
```

If clients cannot connect:

- confirm the VPS firewall and cloud firewall allow the profile's configured TCP port, default `443`
- confirm `--server-host` is the public IP or DNS name clients use
- confirm the profile's `--reality-target` is reachable from the server
- for proxy profiles, confirm the upstream VPN link is configured and reachable from this VPS
- regenerate the client link with `python3 vpnctl.py link CLIENT_NAME --profile PROFILE_NAME`

If quota usage stays at zero:

- confirm clients have an `email` in `data/config.json`
- confirm Xray is running the generated config
- run `python3 vpnctl.py usage --refresh` and check for errors

If `apt` reports `Unable to locate package docker-compose-plugin`:

- rerun `./scripts/install-host.sh` after pulling the latest repo changes
- the installer now adds Docker's official apt repository before installing `docker-compose-plugin`
- if apt reports Docker package conflicts, remove the conflicting distro Docker packages manually and rerun the installer

If Docker reports permission denied for `/var/run/docker.sock`:

```bash
sudo usermod -aG docker $USER
newgrp docker
docker compose version
python3 vpnctl.py up
```

On some VPS sessions, `newgrp docker` is not enough. Log out of SSH and log back in, then run `python3 vpnctl.py up` again.

## Tests

Run the standard-library test suite:

```bash
python3 -m unittest discover -s tests -v
```
