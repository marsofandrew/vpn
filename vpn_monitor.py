"""Opt-in, isolated upstream probes; importing this module performs no I/O.

Production requires a local Docker daemon on Linux and an Xray Compose service
with ``network_mode: host``. ``config_dir`` must be on that daemon's filesystem.
Only calling probe_upstream starts a container or makes a connection. Target
DNS and HTTPS verification belong to vpn_health.probe_path's SOCKS transport."""

from vpn_manager.health.monitor import probe_upstream as probe_upstream

__all__ = ["probe_upstream"]
