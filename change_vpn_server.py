
import argparse
import json
import uuid
import subprocess
import os
import qrcode
from urllib.parse import urlencode
import urllib.request

def get_public_ip():
    try:
        with urllib.request.urlopen('https://ifconfig.me/ip') as response:
            return response.read().decode('utf-8').strip()
    except Exception as e:
        print(f"Could not auto-detect public IP: {e}")
        return None

def apply_changes():
    choice = input("Apply changes to the server? (y/n): ").lower()
    if choice == 'y':
        print("Applying changes to the server...")
        subprocess.run(["docker-compose", "restart"], check=True)
        print("Server restarted.")
    else:
        print("Changes not applied.")

def generate_vless_link(client, vpn_config, server_ip):
    params = {
        "encryption": "none",
        "security": "reality",
        "pbk": vpn_config["keys"]["public_key"],
        "sid": vpn_config["short_id"],
        "sni": vpn_config["dest"].split(':')[0],
        "fp": "chrome",
        "flow": "xtls-rprx-vision"
    }
    query_string = urlencode(params)
    return f"vless://{client['id']}@{server_ip}:443?{query_string}#{client['name']}"

def main():
    parser = argparse.ArgumentParser(description="Manage the VPN server configuration.")
    parser.add_argument("--config", default="vpn_config.json", help="The path to the vpn_config.json file.")
    parser.add_argument("--add-client", help="The name of the new client to add.")
    parser.add_argument("--remove-client", help="The name or UUID of the client to remove.")
    parser.add_argument("--get-link", help="The name of the client to generate a VLESS link for.")
    parser.add_argument("--qr", action="store_true", help="Generate a QR code for the VLESS link.")
    parser.add_argument("--qr-folder", default=".", help="The directory where generated QR codes will be saved.")
    parser.add_argument("--server-ip", help="The public IP address of the server (auto-detected if not provided).")
    args = parser.parse_args()

    with open(args.config, "r") as f:
        vpn_config = json.load(f)

    with open("config.json", "r") as f:
        server_config = json.load(f)

    if args.add_client:
        new_client = {
            "name": args.add_client,
            "id": str(uuid.uuid4())
        }
        vpn_config["clients"].append(new_client)
        server_config["inbounds"][0]["settings"]["clients"].append({
            "id": new_client["id"],
            "email": f"{new_client['name']}@{vpn_config['default_domain']}",
            "flow": "xtls-rprx-vision"
        })
        print(f"Client '{args.add_client}' added.")
        
        with open(args.config, "w") as f:
            json.dump(vpn_config, f, indent=2)
        with open("config.json", "w") as f:
            json.dump(server_config, f, indent=2)
        
        apply_changes()

    elif args.remove_client:
        client_to_remove = None
        for client in vpn_config["clients"]:
            if client["name"] == args.remove_client or client["id"] == args.remove_client:
                client_to_remove = client
                break
        
        if client_to_remove:
            vpn_config["clients"].remove(client_to_remove)
            server_clients = server_config["inbounds"][0]["settings"]["clients"]
            server_clients = [c for c in server_clients if c["id"] != client_to_remove["id"]]
            server_config["inbounds"][0]["settings"]["clients"] = server_clients
            print(f"Client '{client_to_remove['name']}' removed.")

            with open(args.config, "w") as f:
                json.dump(vpn_config, f, indent=2)
            with open("config.json", "w") as f:
                json.dump(server_config, f, indent=2)

            apply_changes()
        else:
            print("Client not found.")

    elif args.get_link:
        server_ip = args.server_ip
        if not server_ip:
            print("Attempting to auto-detect server IP...")
            server_ip = get_public_ip()
            if not server_ip:
                print("Error: Could not auto-detect server IP. Please provide it with the --server-ip flag.")
                return
            print(f"Auto-detected server IP: {server_ip}")

        client_to_link = None
        for client in vpn_config["clients"]:
            if client["name"] == args.get_link:
                client_to_link = client
                break
        
        if client_to_link:
            link = generate_vless_link(client_to_link, vpn_config, server_ip)
            print(f"VLESS link for '{client_to_link['name']}':")
            print(link)

            if args.qr:
                if not os.path.exists(args.qr_folder):
                    os.makedirs(args.qr_folder)
                qr_path = os.path.join(args.qr_folder, f"{client_to_link['name']}.png")
                img = qrcode.make(link)
                img.save(qr_path)
                print(f"QR code saved to {qr_path}")
        else:
            print("Client not found.")

if __name__ == "__main__":
    main()
