"""Temporary CLI paths and an inert Compose adapter for command scenarios."""

import subprocess
import tempfile
from pathlib import Path

from vpn_manager.cli.entrypoint import main


class CliFixture:
    def __init__(self, case):
        directory = tempfile.TemporaryDirectory()
        case.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.state_path = self.root / "state.json"
        self.config_path = self.root / "config.json"
        self.compose_path = self.root / "docker-compose.yaml"
        self.compose_path.write_text("services: {}\n")
        self.calls = []

    def compose(self, compose_file, args, capture=False, port=None):
        self.calls.append((compose_file, args, capture, port))
        return subprocess.CompletedProcess([], 0, stdout="", stderr="")

    def run(self, *command):
        common = [
            "--state",
            str(self.state_path),
            "--config",
            str(self.config_path),
            "--compose-file",
            str(self.compose_path),
        ]
        return main([*common, *command])

    def initialize(self):
        return self.run(
            "init",
            "--server-host",
            "vpn.example.com",
            "--reality-target",
            "www.cloudflare.com:443",
            "--default-domain",
            "example.com",
            "--client",
            "phone",
        )
