
import argparse
import json
import uuid
import secrets
from cryptography.hazmat.primitives.asymmetric import x25519
import base64

def generate_keys():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return {
        "private_key": base64.b64encode(private_key.private_bytes_raw()).decode('utf-8'),
        "public_key": base64.b64encode(public_key.public_bytes_raw()).decode('utf-8')
    }

def main():
    parser = argparse.ArgumentParser(description="Set up the VPN server configuration.")
    parser.add_argument("--default-domain", required=True, help="The default domain for client emails.")
    parser.add_argument("--dest", required=True, help="The destination server for REALITY.")
    parser.add_argument("--client-names", nargs='+', required=True, help="A list of initial client names.")
    parser.add_argument("--output-file", default="vpn_config.json", help="The path to store the generated keys and configuration.")
    args = parser.parse_args()

    keys = generate_keys()
    short_id = secrets.token_hex(8)

    clients = []
    for name in args.client_names:
        clients.append({
            "name": name,
            "id": str(uuid.uuid4())
        })

    with open("template_config.json", "r") as f:
        config_template = json.load(f)

    config_template["inbounds"][0]["settings"]["clients"] = [
        {
            "id": client["id"],
            "email": f"{client['name']}@{args.default_domain}",
            "flow": "xtls-rprx-vision"
        } for client in clients
    ]
    config_template["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] = keys["private_key"]
    config_template["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"] = [short_id]
    config_template["inbounds"][0]["streamSettings"]["realitySettings"]["dest"] = args.dest
    config_template["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"] = [args.dest.split(':')[0]]


    with open("config.json", "w") as f:
        json.dump(config_template, f, indent=2)

    vpn_config = {
        "keys": keys,
        "short_id": short_id,
        "clients": clients,
        "default_domain": args.default_domain,
        "dest": args.dest
    }

    with open(args.output_file, "w") as f:
        json.dump(vpn_config, f, indent=2)

    print(f"Configuration saved to {args.output_file}")
    print(f"Server config updated in config.json")

if __name__ == "__main__":
    main()
