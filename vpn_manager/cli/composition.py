"""Assemble concrete adapters at the CLI entry boundary."""

import time
from functools import partial

import vpn_monitor
from vpn_manager import accounting, clock
from vpn_manager.cli import (
    clients,
    exports,
    health,
    initialization,
    inventory,
    profiles,
    routing,
    runtime,
    usage,
)
from vpn_manager.health.service import HealthService
from vpn_manager.ports import StateStore
from vpn_manager.state.storage import JsonStateStore
from vpn_manager.xray import deployment
from vpn_manager.xray import runtime as xray_runtime


def monitoring(compose_file, config_dir) -> HealthService:
    probe = partial(
        vpn_monitor.probe_upstream,
        compose_file=compose_file,
        config_dir=config_dir,
        run_compose=xray_runtime.run_compose,
    )
    return HealthService(probe, time.time, clock.utc_now)


def services() -> tuple[
    StateStore, accounting.UsageService, deployment.DeploymentService
]:
    store = JsonStateStore()
    usage = accounting.UsageService(
        xray_runtime.XrayStatistics(), clock.SystemCalendar()
    )
    transactions = deployment.DeploymentService(
        store, xray_runtime.ComposeRuntime(), usage.sample
    )
    return store, usage, transactions


def handlers(store, usage, transactions):
    result = {}
    result.update(_exports(store))
    result.update(_health(monitoring, transactions.persist, store))
    result.update(
        _runtime(xray_runtime.run_compose, transactions.deploy, usage.sample, store)
    )
    result.update(_initialization(transactions.persist, store))
    result.update(_routing(transactions.persist, store))
    result.update(_clients(transactions.persist, store))
    result.update(_usage(transactions.persist, usage.sample, store))
    result.update(_profiles(transactions.persist, store))
    result.update(_inventory(store))
    return result


def _exports(store):
    return {
        exports.command_endpoint: partial(exports.command_endpoint, store=store),
        exports.command_subscription: partial(
            exports.command_subscription, store=store
        ),
    }


def _health(monitoring, persist, store):
    return {
        health.command_health: partial(
            health.command_health, monitoring=monitoring, persist=persist, store=store
        ),
    }


def _runtime(compose, deploy, sample, store):
    return {
        runtime.command_up: partial(runtime.command_up, deploy=deploy, store=store),
        runtime.command_restart: partial(
            runtime.command_restart, deploy=deploy, store=store
        ),
        runtime.command_down: partial(
            runtime.command_down, compose=compose, sample=sample, store=store
        ),
        runtime.command_status: partial(runtime.command_status, compose=compose),
        runtime.command_logs: partial(runtime.command_logs, compose=compose),
        runtime.command_validate: partial(runtime.command_validate, compose=compose),
    }


def _initialization(persist, store):
    return {
        initialization.command_init: partial(initialization.command_init, store=store),
        initialization.command_import_config: partial(
            initialization.command_import_config, store=store
        ),
        initialization.command_render: partial(
            initialization.command_render, persist=persist, store=store
        ),
    }


def _routing(persist, store):
    return {
        routing.command_upstream_show: partial(
            routing.command_upstream_show, store=store
        ),
        routing.command_upstream_set: partial(
            routing.command_upstream_set, persist=persist, store=store
        ),
        routing.command_upstream_clear: partial(
            routing.command_upstream_clear, persist=persist, store=store
        ),
        routing.command_upstream_list: partial(
            routing.command_upstream_list, store=store
        ),
        routing.command_upstream_enabled: partial(
            routing.command_upstream_enabled, persist=persist, store=store
        ),
        routing.command_route: partial(
            routing.command_route, persist=persist, store=store
        ),
        routing.command_policy: partial(
            routing.command_policy, persist=persist, store=store
        ),
        routing.command_node: partial(
            routing.command_node, persist=persist, store=store
        ),
    }


def _clients(persist, store):
    return {
        clients.command_client_add: partial(
            clients.command_client_add, persist=persist, store=store
        ),
        clients.command_client_remove: partial(
            clients.command_client_remove, persist=persist, store=store
        ),
        clients.command_client_list: partial(
            clients.command_client_list, persist=persist, store=store
        ),
        clients.command_client_enabled: partial(
            clients.command_client_enabled, persist=persist, store=store
        ),
        clients.command_link: partial(
            clients.command_link, persist=persist, store=store
        ),
        clients.command_client_enable: partial(
            clients.command_client_enable, persist=persist, store=store
        ),
        clients.command_client_disable: partial(
            clients.command_client_disable, persist=persist, store=store
        ),
    }


def _usage(persist, sample, store):
    return {
        usage.command_quota_set: partial(
            usage.command_quota_set, persist=persist, store=store
        ),
        usage.command_quota_reset: partial(
            usage.command_quota_reset, persist=persist, store=store
        ),
        usage.command_quota_enforce: partial(
            usage.command_quota_enforce, persist=persist, sample=sample, store=store
        ),
        usage.command_usage: partial(
            usage.command_usage, persist=persist, sample=sample, store=store
        ),
    }


def _profiles(persist, store):
    return {
        profiles.command_profile_list: partial(
            profiles.command_profile_list, persist=persist, store=store
        ),
        profiles.command_profile_add: partial(
            profiles.command_profile_add, persist=persist, store=store
        ),
        profiles.command_profile_remove: partial(
            profiles.command_profile_remove, persist=persist, store=store
        ),
        profiles.command_profile_outbound: partial(
            profiles.command_profile_outbound, persist=persist, store=store
        ),
    }


def _inventory(store):
    return {
        inventory.command_inventory: partial(inventory.command_inventory, store=store),
        inventory.command_upstream_bind: partial(
            inventory.command_upstream_bind, store=store
        ),
    }
