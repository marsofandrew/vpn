import argparse

import vpn_inventory
from vpn_manager import errors as app_errors
from vpn_manager import files as app_files


def command_inventory(args: argparse.Namespace, *, store) -> None:
    try:
        if args.inventory_command == "example":
            if args.file.exists():
                raise app_errors.VpnctlError(
                    "inventory already exists; choose a new file"
                )
            app_files.write_json(args.file, vpn_inventory.example_inventory())
            print(f"Inventory example written to {args.file}")
            return
        inventory = app_files.load_json(args.file)
        vpn_inventory.validate_inventory(inventory)
        if args.inventory_command == "validate" and args.with_runtime:
            state = store.load(args.state)
            vpn_inventory.validate_node_references(
                inventory,
                [state["node"]["id"], *state.get("upstream_nodes", {}).values()],
            )
            nodes = {node["id"]: node for node in inventory["nodes"]}
            if nodes[state["node"]["id"]]["role"] not in {
                state["node"]["role"],
                "both",
            }:
                raise app_errors.VpnctlError(
                    "local runtime role does not match inventory"
                )
            if any(
                nodes[node_id]["role"] not in {"exit", "both"}
                for node_id in state.get("upstream_nodes", {}).values()
            ):
                raise app_errors.VpnctlError(
                    "upstream bindings must reference exit-capable nodes"
                )
        if args.inventory_command == "list":
            for node in vpn_inventory.summary_nodes(inventory):
                print(
                    f"{node['id']}\trole={node['role']}\tconnectivity={node['mode']}\thost={node['host'] or '-'}"
                )
        else:
            print("Inventory is valid.")
    except ValueError as error:
        raise app_errors.VpnctlError(str(error)) from None


def command_upstream_bind(args: argparse.Namespace, *, store) -> None:
    state = store.load(args.state)
    if args.name not in state["upstreams"]:
        raise app_errors.VpnctlError("unknown upstream")
    try:
        inventory = app_files.load_json(args.inventory)
        vpn_inventory.validate_node_references(inventory, [args.node])
        node = next(node for node in inventory["nodes"] if node["id"] == args.node)
        if node["role"] not in {"exit", "both"}:
            raise app_errors.VpnctlError("upstream node must support exit traffic")
    except ValueError as error:
        raise app_errors.VpnctlError(str(error)) from None
    state.setdefault("upstream_nodes", {})[args.name] = args.node
    store.save(args.state, state)
    print(f"Bound upstream {args.name} to inventory node {args.node}")
