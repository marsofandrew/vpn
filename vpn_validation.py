"""Nonmutating structural checks for v4 state, before semantic validation.

Unknown metadata is retained. Defaulted fields may be absent, but present
fields must have their command-compatible types. Transport semantics remain
the responsibility of vpn_transports. Paths use positions instead of stored
mapping keys so errors never disclose credentials or operator-provided names."""

from vpn_manager.state.shape import validate_state_shape as validate_state_shape

__all__ = ["validate_state_shape"]
