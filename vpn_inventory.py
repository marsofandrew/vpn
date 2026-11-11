"""Credential-free infrastructure metadata, independent of VPN runtime state."""

from vpn_manager.inventory import InventoryError as InventoryError
from vpn_manager.inventory import example_inventory as example_inventory
from vpn_manager.inventory import summary_nodes as summary_nodes
from vpn_manager.inventory import validate_inventory as validate_inventory
from vpn_manager.inventory import validate_node_references as validate_node_references

__all__ = [
    "InventoryError",
    "validate_inventory",
    "validate_node_references",
    "summary_nodes",
    "example_inventory",
]
