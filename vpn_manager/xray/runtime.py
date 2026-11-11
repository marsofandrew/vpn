import json
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import vpn_transports
from vpn_manager import errors as app_errors
from vpn_manager import files as app_files
from vpn_manager import settings as app_settings


def compose_base_command(compose_file: Path) -> list[str]:
    if shutil.which("docker"):
        return ["docker", "compose", "-f", str(compose_file)]
    if shutil.which("docker-compose"):
        return ["docker-compose", "-f", str(compose_file)]
    raise app_errors.VpnctlError("docker compose is not installed")


def is_docker_permission_error(error: subprocess.CalledProcessError) -> bool:
    text = " ".join(
        part.lower()
        for part in (str(error), error.stderr or "", error.stdout or "")
        if part
    )
    return ("/var/run/docker.sock" in text and "permission denied" in text) or (
        "docker api" in text and "permission denied" in text
    )


def docker_permission_error() -> app_errors.VpnctlError:
    return app_errors.VpnctlError(
        "Docker is installed, but this user cannot access /var/run/docker.sock. "
        "Run 'sudo usermod -aG docker $USER', then log out and back in or run 'newgrp docker'. "
        "Temporary workaround: run this command with sudo."
    )


def run_compose(
    compose_file: Path,
    args: list[str],
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    command = compose_base_command(compose_file) + args
    try:
        return subprocess.run(
            command,
            check=True,
            text=True,
            capture_output=capture,
            timeout=None if "--follow" in args or "-f" in args else 120,
        )
    except subprocess.CalledProcessError as error:
        if is_docker_permission_error(error):
            raise docker_permission_error() from error
        raise


def restart_xray(compose_file: Path, state: dict[str, Any] | None = None) -> None:
    run_compose(
        compose_file,
        ["up", "-d", "--force-recreate", app_settings.XRAY_SERVICE],
        capture=True,
    )


def runtime_epoch(compose_file: Path) -> str:
    result = run_compose(
        compose_file, ["ps", "-q", app_settings.XRAY_SERVICE], capture=True
    )
    container_id = result.stdout.strip()
    if not container_id:
        raise app_errors.VpnctlError("Xray is not running")
    result = subprocess.run(
        [
            "docker",
            "inspect",
            "--format",
            "{{.Id}} {{.State.StartedAt}} {{.State.Running}}",
            container_id,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if not result.stdout.strip().endswith(" true"):
        raise app_errors.VpnctlError("Xray is not running")
    return result.stdout.strip()


def validate_native(compose_file: Path, candidate_path: Path) -> None:
    completed = run_compose(
        compose_file,
        [
            "run",
            "--rm",
            "--no-deps",
            "-v",
            f"{candidate_path.resolve()}:/etc/xray/candidate.json:ro",
            app_settings.XRAY_SERVICE,
            "run",
            "-test",
            "-config",
            "/etc/xray/candidate.json",
        ],
        capture=True,
    )
    candidate = app_files.load_json(candidate_path)
    ech_enabled = any(
        entry.get("streamSettings", {}).get("tlsSettings", {}).get(field)
        for entry in candidate.get("inbounds", []) + candidate.get("outbounds", [])
        for field in ("echConfigList", "echServerKeys")
    )
    if ech_enabled and not re.match(
        r"Xray " + re.escape(vpn_transports.PINNED_XRAY_VERSION) + r"\s",
        completed.stdout,
    ):
        raise app_errors.VpnctlError(
            "ECH requires the tested pinned Xray version; check XRAY_IMAGE"
        )


def validate_config_mount(compose_file: Path, config_path: Path) -> None:
    completed = run_compose(compose_file, ["config", "--format", "json"], capture=True)
    try:
        resolved = json.loads(completed.stdout)
        volumes = resolved["services"][app_settings.XRAY_SERVICE]["volumes"]
        if not isinstance(volumes, list) or any(
            not isinstance(volume, dict) for volume in volumes
        ):
            raise ValueError
        mounts = [
            volume
            for volume in volumes
            if volume.get("target") == "/etc/xray/config.json"
        ]
        if len(mounts) != 1:
            raise ValueError
        mount = mounts[0]
        if (
            mount.get("type") != "bind"
            or mount.get("read_only") is not True
            or not isinstance(mount.get("source"), str)
            or not mount["source"]
        ):
            raise ValueError
        source = Path(mount["source"])
        if not source.is_absolute():
            source = compose_file.resolve().parent / source
        if source.resolve() != config_path.resolve():
            raise ValueError
    except (KeyError, TypeError, ValueError, OSError, RuntimeError):
        raise app_errors.VpnctlError(
            "Xray must bind the requested configuration read-only at /etc/xray/config.json"
        ) from None


def verify_xray(compose_file: Path, config: dict[str, Any]) -> None:
    deadline = time.monotonic() + 15
    while True:
        try:
            epoch = runtime_epoch(compose_file)
            query_xray_stats(compose_file, reset=False, state={})
            for inbound in config["inbounds"]:
                with socket.create_connection(
                    ("127.0.0.1", inbound["port"]), timeout=1
                ):
                    pass
            time.sleep(0.25)
            if epoch != runtime_epoch(compose_file):
                raise app_errors.VpnctlError("Xray restarted during health check")
            return
        except (OSError, app_errors.VpnctlError, subprocess.CalledProcessError):
            if time.monotonic() >= deadline:
                raise app_errors.VpnctlError(
                    "Xray failed API/listener health checks"
                ) from None
            time.sleep(0.25)


def query_xray_stats(
    compose_file: Path, reset: bool, state: dict[str, Any]
) -> dict[str, Any]:
    args = [
        "exec",
        "-T",
        app_settings.XRAY_SERVICE,
        "xray",
        "api",
        "statsquery",
        "--server=127.0.0.1:10085",
        "-pattern",
        "user>>>",
    ]
    if reset:
        args.append("-reset")
    completed = run_compose(compose_file, args, capture=True)
    output = completed.stdout.strip()
    if not output:
        return {"stat": []}
    return json.loads(output)


class ComposeRuntime:
    def check_mount(self, compose: Path, config: Path) -> None:
        validate_config_mount(compose, config)

    def validate(self, compose: Path, candidate: Path) -> None:
        validate_native(compose, candidate)

    def running(self, compose: Path) -> bool:
        return bool(
            run_compose(
                compose, ["ps", "-q", app_settings.XRAY_SERVICE], capture=True
            ).stdout.strip()
        )

    def restart(self, compose: Path, state: dict[str, Any] | None = None) -> None:
        if state is None:
            restart_xray(compose)
        else:
            restart_xray(compose, state)

    def verify(self, compose: Path, config: dict[str, Any]) -> None:
        verify_xray(compose, config)

    def stop(self, compose: Path) -> None:
        run_compose(compose, ["stop", app_settings.XRAY_SERVICE], capture=True)


class XrayStatistics:
    def epoch(self, compose: Path) -> str:
        return runtime_epoch(compose)

    def read(self, compose: Path, state: dict[str, Any]) -> dict[str, Any]:
        return query_xray_stats(compose, reset=False, state=state)
