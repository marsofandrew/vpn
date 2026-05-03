#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
SERVICE_NAME="vpnctl-quota"
DOCKER_APT_KEYRING="/etc/apt/keyrings/docker.asc"
DOCKER_APT_SOURCE="/etc/apt/sources.list.d/docker.list"
INSTALL_USER="${SUDO_USER:-$USER}"

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This installer supports Ubuntu/Debian hosts with apt-get." >&2
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required for host installation." >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg python3 python3-cryptography python3-qrcode

if ! sudo docker compose version >/dev/null 2>&1; then
  . /etc/os-release
  DOCKER_APT_CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
  if [ -z "${DOCKER_APT_CODENAME}" ]; then
    echo "Could not detect Ubuntu/Debian apt codename from /etc/os-release." >&2
    exit 1
  fi
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${ID}/gpg" | sudo tee "${DOCKER_APT_KEYRING}" >/dev/null
  sudo chmod a+r "${DOCKER_APT_KEYRING}"

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=${DOCKER_APT_KEYRING}] https://download.docker.com/linux/${ID} ${DOCKER_APT_CODENAME} stable" \
    | sudo tee "${DOCKER_APT_SOURCE}" >/dev/null

  sudo apt-get update
  if ! sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
    echo "Docker official packages could not be installed." >&2
    echo "If apt reports package conflicts, remove conflicting distro Docker packages manually and rerun this script." >&2
    exit 1
  fi
fi

if ! sudo docker compose version >/dev/null 2>&1; then
  echo "docker compose is still unavailable after installation." >&2
  exit 1
fi

sudo systemctl enable --now docker
sudo groupadd -f docker
if [ "${INSTALL_USER}" != "root" ]; then
  sudo usermod -aG docker "${INSTALL_USER}"
fi

if command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -q "Status: active"; then
  sudo ufw allow 443/tcp
fi

sudo tee "/etc/systemd/system/${SERVICE_NAME}.service" >/dev/null <<SERVICE
[Unit]
Description=Enforce vpnctl Xray client traffic quotas
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
WorkingDirectory=${REPO_DIR}
ExecStart=${PYTHON_BIN} ${REPO_DIR}/vpnctl.py quota enforce
SERVICE

sudo tee "/etc/systemd/system/${SERVICE_NAME}.timer" >/dev/null <<TIMER
[Unit]
Description=Run vpnctl quota enforcement every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Unit=${SERVICE_NAME}.service

[Install]
WantedBy=timers.target
TIMER

sudo systemctl daemon-reload
sudo systemctl enable --now "${SERVICE_NAME}.timer"

echo "Host setup complete."
if [ "${INSTALL_USER}" != "root" ]; then
  echo "User '${INSTALL_USER}' was added to the docker group."
  echo "Run 'newgrp docker' or log out and back in before running vpnctl without sudo."
fi
echo "Initialize the VPN with: ${PYTHON_BIN} ${REPO_DIR}/vpnctl.py init --server-host YOUR_IP_OR_DOMAIN --reality-target www.cloudflare.com:443 --client phone"
