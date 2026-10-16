"""Opaque semantic-validator bindings issued by trusted closed factories.

Reviewed factories live with workflow contracts. The private mint is also used
by explicit synthetic test support; it is not an untrusted registration API.
This binds configuration and callable identity, not a Python sandbox or proof
that arbitrary trusted Python code preserves its semantics.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType


_SEAL = object()


def _plain(value):
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("validator_policy_invalid")
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise ValueError("validator_policy_invalid")


def _encoded(value):
    return json.dumps(_plain(value), sort_keys=True, separators=(",", ":"), allow_nan=False)


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


class ValidatorBinding:
    """Immutable factory result; direct construction is deliberately unavailable."""

    __slots__ = ("policy", "role", "policy_pin", "_identity", "_callback", "_original", "_seal")

    def __init__(self, *args, **kwargs):
        raise TypeError("validator_factory_required")

    def __setattr__(self, name, value):
        raise AttributeError("immutable_validator_binding")

    def _check_integrity(self):
        try:
            callback, code, call_method, encoded, role, identity = self._original
            valid = (self._seal is _SEAL and self._callback is callback
                     and getattr(callback, "__code__", None) is code
                     and type(callback).__call__ is call_method
                     and self.role == role and self._identity == identity
                     and _encoded(self.policy) == encoded
                     and self.policy_pin == hashlib.sha256(encoded.encode()).hexdigest())
        except (AttributeError, TypeError, ValueError):
            valid = False
        if not valid:
            raise ValueError("validator_binding_changed")

    def check(self, contract):
        self._check_integrity()
        if (contract.workflow_id, contract.version) != self._identity:
            raise ValueError("validator_contract_mismatch")

    def __call__(self, attempt, context):
        self._check_integrity()
        return self._callback(attempt, context)


def _bind_validator(policy, role, callback, contract_identity):
    """Private trusted-factory mint; callers must establish reviewed provenance.

    Public application setup uses the closed workflow resolver. Test support
    must mark its policy ``synthetic_test`` and cannot bind reviewed contracts.
    """
    if (not isinstance(policy, Mapping) or not callable(callback)
            or type(role) is not str or not role
            or not isinstance(contract_identity, tuple) or len(contract_identity) != 2
            or any(type(item) is not str or not item for item in contract_identity)):
        raise ValueError("validator_binding_invalid")
    encoded = _encoded(policy)
    binding = object.__new__(ValidatorBinding)
    values = {
        "policy": _freeze(json.loads(encoded)), "role": role,
        "policy_pin": hashlib.sha256(encoded.encode()).hexdigest(),
        "_identity": contract_identity, "_callback": callback, "_seal": _SEAL,
        "_original": (callback, getattr(callback, "__code__", None), type(callback).__call__,
                      encoded, role, contract_identity),
    }
    for name, value in values.items():
        object.__setattr__(binding, name, value)
    return binding
