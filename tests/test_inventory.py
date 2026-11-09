import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

import vpn_inventory as inventory


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.inventory = inventory.example_inventory()

    def node(self):
        return self.inventory["nodes"][0]

    def test_example_round_trips_and_has_stable_expected_ids(self):
        original = copy.deepcopy(self.inventory)
        self.assertIsNone(inventory.validate_inventory(self.inventory))
        self.assertEqual(self.inventory, original)
        self.assertEqual(json.loads(json.dumps(self.inventory)), original)
        self.assertEqual([node["id"] for node in self.inventory["nodes"]],
                         ["ru-vps", "ru-home", "ny-vps", "pt-home"])
        for node in self.inventory["nodes"]:
            if node["id"].endswith("-home"):
                self.assertEqual(node["connectivity"], {"mode": "outbound"})
        self.node()["connectivity"]["host"] = "changed.example.com"
        self.node()["transports"].append("wireguard")
        self.assertEqual(inventory.example_inventory(), original)

    def test_empty_and_minimal_inventory(self):
        inventory.validate_inventory({"version": 1, "nodes": []})
        for mode in ("public", "outbound"):
            with self.subTest(mode=mode):
                inventory.validate_inventory({"version": 1, "nodes": [
                    {"id": "node-1", "role": "both", "connectivity": {"mode": mode}},
                ]})

    def test_top_level_shape_is_strict(self):
        for value in (None, [], "inventory", {}, {"version": 1},
                      {"nodes": []}, {"version": 1, "nodes": [], "extra": True}):
            with self.subTest(value=value), self.assertRaises(inventory.InventoryError):
                inventory.validate_inventory(value)
        for version in (True, False, 1.0, "1", None, 0, 2):
            with self.subTest(version=version), self.assertRaises(inventory.InventoryError):
                inventory.validate_inventory({"version": version, "nodes": []})
        for nodes in (None, {}, (), "nodes", 1):
            with self.subTest(nodes=nodes), self.assertRaises(inventory.InventoryError):
                inventory.validate_inventory({"version": 1, "nodes": nodes})

    def test_required_node_fields_and_unknown_fields(self):
        for field in ("id", "role", "connectivity"):
            candidate = copy.deepcopy(self.inventory)
            del candidate["nodes"][0][field]
            with self.subTest(missing=field), self.assertRaises(inventory.InventoryError):
                inventory.validate_inventory(candidate)
        for node in (None, [], "node", 1, {**self.node(), "hostname": "extra.example.com"}):
            with self.subTest(node=node), self.assertRaises(inventory.InventoryError):
                inventory.validate_inventory({"version": 1, "nodes": [node]})

    def test_ids_are_unique_and_never_normalized_or_generated(self):
        self.inventory["nodes"].append(copy.deepcopy(self.node()))
        with self.assertRaisesRegex(inventory.InventoryError, "unique"):
            inventory.validate_inventory(self.inventory)
        self.inventory["nodes"].pop()
        for node_id in (None, 1, True, [], {}, "", " node", "NODE", "-node",
                        "node/name", "node\n", "n" * 65, "nødé"):
            with self.subTest(node_id=node_id), self.assertRaises(inventory.InventoryError):
                self.node()["id"] = node_id
                inventory.validate_inventory(self.inventory)
        for node_id in ("n", "n" * 64, "node_1", "11111111-2222-3333-4444-555555555555"):
            self.node()["id"] = node_id
            inventory.validate_inventory(self.inventory)
            self.assertEqual(self.node()["id"], node_id)

    def test_roles_and_modes(self):
        for role in ("gateway", "exit", "both"):
            self.node()["role"] = role
            inventory.validate_inventory(self.inventory)
        for role in (None, [], {}, True, "Gateway", "relay", ""):
            with self.subTest(role=role), self.assertRaises(inventory.InventoryError):
                self.node()["role"] = role
                inventory.validate_inventory(self.inventory)
        self.node()["role"] = "both"
        for connectivity in (None, [], {}, {"mode": "direct"}, {"mode": []},
                             {"mode": None}, {"mode": True},
                             {"mode": "public", "port": 443}):
            with self.subTest(connectivity=connectivity), self.assertRaises(inventory.InventoryError):
                self.node()["connectivity"] = connectivity
                inventory.validate_inventory(self.inventory)

    def test_country_is_optional_and_strict_when_present(self):
        del self.node()["country"]
        inventory.validate_inventory(self.inventory)
        for country in (None, 1, [], "", "ru", "RUS", "R", " RU", "ŘU"):
            with self.subTest(country=country), self.assertRaises(inventory.InventoryError):
                self.node()["country"] = country
                inventory.validate_inventory(self.inventory)

    def test_hosts_are_syntax_only_and_optional_in_both_modes(self):
        for mode in ("public", "outbound"):
            for host in ("example.com", "vpn.example.com.", "localhost", "203.0.113.10",
                         "100.64.0.1", "192.168.1.2", "2001:db8::1", "::1"):
                with self.subTest(mode=mode, host=host):
                    self.node()["connectivity"] = {"mode": mode, "host": host}
                    inventory.validate_inventory(self.inventory)
            self.node()["connectivity"] = {"mode": mode}
            inventory.validate_inventory(self.inventory)

    def test_invalid_hosts_and_embedded_credentials_are_rejected_without_echoing(self):
        for host in (None, 1, [], "", " ", "vpn.example.com\n", "a b", "a..b",
                     "https://example.com", "example.com:443", "example.com/path",
                     "user:NEVER-ECHO@example.com", "example.com?token=NEVER-ECHO",
                     "example.com#fragment", "[::1]", "fe80::1%eth0", "999.1.1.1",
                     "-vpn.example.com", "vpn_.example.com", "éxample.com", "a" * 64 + ".com",
                     ".", "a." * 127 + "com"):
            with self.subTest(host=host):
                self.node()["connectivity"]["host"] = host
                with self.assertRaises(inventory.InventoryError) as raised:
                    inventory.validate_inventory(self.inventory)
                self.assertNotIn("NEVER-ECHO", str(raised.exception))

    def test_transport_names_are_optional_unique_identifiers(self):
        del self.node()["transports"]
        inventory.validate_inventory(self.inventory)
        for transports in ([], ["vless-reality", "wireguard", "future_transport"]):
            self.node()["transports"] = transports
            inventory.validate_inventory(self.inventory)
        for transports in (None, {}, (), "wireguard", ["wireguard", "wireguard"],
                           [None], [{}], [[]], [""], ["WireGuard"], ["vless://NEVER-ECHO"],
                           ["a" * 65]):
            with self.subTest(transports=transports), self.assertRaises(inventory.InventoryError):
                self.node()["transports"] = transports
                inventory.validate_inventory(self.inventory)

    def test_secret_fields_are_rejected_recursively_and_case_insensitively(self):
        for field in ("uuid", "client_uuid", "UUID", "password", "passphrase", "psk",
                      "private_key", "privateKey", "api-token", "apiKey", "credentials",
                      "secret", "authorization", "username", "keys"):
            for location in ("root", "node", "connectivity", "nested"):
                with self.subTest(field=field, location=location):
                    candidate = inventory.example_inventory()
                    if location == "root":
                        target = candidate
                    elif location == "node":
                        target = candidate["nodes"][0]
                    elif location == "connectivity":
                        target = candidate["nodes"][0]["connectivity"]
                    else:
                        target = {}
                        candidate["nodes"][0]["transports"] = [{"unknown": [target]}]
                    target[field] = "NEVER-ECHO"
                    with self.assertRaisesRegex(inventory.InventoryError, "secret fields") as raised:
                        inventory.validate_inventory(candidate)
                    self.assertNotIn("NEVER-ECHO", str(raised.exception))

    def test_unknown_field_names_and_values_are_not_echoed(self):
        self.node()["NEVER-ECHO"] = "NEVER-ECHO"
        with self.assertRaises(inventory.InventoryError) as raised:
            inventory.validate_inventory(self.inventory)
        self.assertNotIn("NEVER-ECHO", str(raised.exception))

    def test_non_string_keys_and_cycles_fail_safely(self):
        for key in (1, None, ("key",)):
            candidate = inventory.example_inventory()
            candidate[key] = "value"
            with self.subTest(key=key), self.assertRaises(inventory.InventoryError):
                inventory.validate_inventory(candidate)
        self.inventory["extra"] = self.inventory
        with self.assertRaisesRegex(inventory.InventoryError, "cyclic"):
            inventory.validate_inventory(self.inventory)

    def test_summaries_are_safe_ordered_and_independent(self):
        original = copy.deepcopy(self.inventory)
        rows = inventory.summary_nodes(self.inventory)
        self.assertEqual(rows[0], {
            "id": "ru-vps", "role": "gateway", "country": "RU", "mode": "public",
            "host": "ru-vps.example.com", "transports": ["vless-reality"],
        })
        self.assertEqual([row["id"] for row in rows], [node["id"] for node in original["nodes"]])
        self.assertIsNone(rows[1]["host"])
        rows[0]["transports"].append("changed")
        rows[0]["id"] = "changed"
        self.assertEqual(self.inventory, original)
        self.assertEqual(inventory.summary_nodes({"version": 1, "nodes": []}), [])
        del self.node()["country"]
        del self.node()["transports"]
        row = inventory.summary_nodes(self.inventory)[0]
        self.assertIsNone(row["country"])
        self.assertEqual(row["transports"], [])

    def test_summaries_reject_secrets_and_invalid_metadata(self):
        self.node()["uuid"] = "NEVER-ECHO"
        with self.assertRaises(inventory.InventoryError):
            inventory.summary_nodes(self.inventory)
        del self.node()["uuid"]
        self.node()["role"] = "invalid"
        with self.assertRaises(inventory.InventoryError):
            inventory.summary_nodes(self.inventory)

    def test_external_node_references_are_validated_separately(self):
        original = copy.deepcopy(self.inventory)
        for references in ([], ["ru-vps"], ["ru-home", "ny-vps", "pt-home", "ru-home"]):
            self.assertIsNone(inventory.validate_node_references(self.inventory, references))
        for references in ("ru-vps", None, {}, ("ru-vps",), ["unknown"], [None], [[]],
                           ["RU-VPS"], ["ru-vps", "missing"]):
            with self.subTest(references=references), self.assertRaises(inventory.InventoryError):
                inventory.validate_node_references(self.inventory, references)
        self.assertEqual(self.inventory, original)
        self.inventory["version"] = 2
        with self.assertRaises(inventory.InventoryError):
            inventory.validate_node_references(self.inventory, [])

    def test_module_and_apis_work_without_runtime_or_site_packages(self):
        root = Path(__file__).resolve().parents[1]
        code = """
import importlib.util
import json
import sys
spec = importlib.util.spec_from_file_location('inventory', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
value = module.example_inventory()
module.validate_inventory(value)
module.validate_node_references(value, ['ru-home'])
assert len(module.summary_nodes(value)) == 4
assert 'vpnctl' not in sys.modules
assert 'qrcode' not in sys.modules
assert 'cryptography' not in sys.modules
json.dumps(value)
"""
        subprocess.run([sys.executable, "-I", "-S", "-B", "-c", code,
                        str(root / "vpn_inventory.py")], check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
