
# VPN Setup with Xray-core

This project provides a set of Python scripts to easily set up and manage a VPN server using Xray-core with VLESS and REALITY protocols, running inside a Docker container.

## Prerequisites

- Python 3
- Docker and Docker Compose
- Required Python libraries:
  ```bash
  pip install qrcode cryptography
  ```

## Setup

1.  **Initial Server Setup**

    The `setup_vpn_server.py` script generates the initial server configuration, keys, and client UUIDs.

    **Usage:**

    ```bash
    python setup_vpn_server.py --default-domain <your-domain> --dest <destination-server> --client-names <client1> <client2> ...
    ```

    **Arguments:**

    - `--default-domain`: The domain to be used for client emails (e.g., `example.com`).
    - `--dest`: The destination server for REALITY (e.g., `www.google.com:443`).
    - `--client-names`: A space-separated list of initial client names.
    - `--output-file` (optional): The path to store the generated keys and configuration. Defaults to `vpn_config.json`.

    **Example:**

    ```bash
    python setup_vpn_server.py --default-domain myvpn.com --dest www.amazon.com:443 --client-names user1 user2
    ```

    This will:
    - Create `config.json` with the server configuration.
    - Create `vpn_config.json` to store keys, the short ID, and client information for future management.

2.  **Build and Run the Docker Container**

    ```bash
    docker-compose up --build -d
    ```

## Management

The `change_vpn_server.py` script allows you to manage the VPN server configuration after the initial setup.

**Usage:**

```bash
python change_vpn_server.py [options]
```

**Options:**

- `--config`: The path to the `vpn_config.json` file. Defaults to `vpn_config.json`.
- `--add-client <name>`: Add a new client with the given name.
- `--remove-client <name-or-uuid>`: Remove a client by name or UUID.
- `--get-link <name>`: Generate a VLESS link for an existing client. Requires `--server-ip`.
- `--qr`: Generate a QR code for the VLESS link.
- `--qr-folder <path>`: The directory to save the generated QR code. Defaults to the current directory.
- `--server-ip <ip-address>`: The public IP address of your server. If not provided, the script will attempt to detect it automatically.

**Examples:**

-   **Add a new client:**

    ```bash
    python change_vpn_server.py --add-client user3
    ```
    The script will prompt for confirmation to apply the changes and restart the server.

-   **Remove a client:**

    ```bash
    python change_vpn_server.py --remove-client user1
    ```
    The script will prompt for confirmation to apply the changes and restart the server.

-   **Get a VLESS link and QR code:**

    ```bash
    python change_vpn_server.py --get-link user2 --server-ip 123.45.67.89 --qr --qr-folder ./qrcodes
    ```
    This will print the VLESS link and save a QR code to `./qrcodes/user2.png`.
