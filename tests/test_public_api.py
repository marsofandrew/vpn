import importlib
import subprocess
import sys
import unittest
from pathlib import Path

import vpn_health
import vpn_monitor
import vpn_transports
import vpn_validation
from vpn_manager.health import measurement, monitor, policies
from vpn_manager.state import shape
from vpn_manager.transports import links, rendering


class PublicApiTests(unittest.TestCase):
    def test_explicit_public_reexports(self):
        importlib.reload(vpn_monitor)
        pairs = (
            (vpn_health.probe_path, measurement.probe_path),
            (vpn_health.record_probe, policies.record_probe),
            (vpn_health.select_route, policies.select_route),
            (vpn_monitor.probe_upstream, monitor.probe_upstream),
            (vpn_transports.parse_link, links.parse_link),
            (vpn_transports.render_stream, rendering.render_stream),
            (vpn_validation.validate_state_shape, shape.validate_state_shape),
        )
        for facade, implementation in pairs:
            self.assertIs(facade, implementation)

    def test_inventory_and_shape_import_without_runtime_initialization(self):
        root = str(Path(__file__).resolve().parents[1])
        code = "\n".join(
            (
                "import sys; sys.path.insert(0, sys.argv[1])",
                "import vpn_inventory, vpn_validation",
                "assert 'vpnctl' not in sys.modules",
                "assert 'vpn_manager.cli.entrypoint' not in sys.modules",
                "assert 'vpn_manager.xray.runtime' not in sys.modules",
                "assert 'qrcode' not in sys.modules",
                "assert 'cryptography' not in sys.modules",
            )
        )
        subprocess.run([sys.executable, "-I", "-S", "-B", "-c", code, root], check=True)
