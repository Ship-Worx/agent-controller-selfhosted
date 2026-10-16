"""Explicit synthetic callbacks for generic authority tests, never reviewed apps."""
import hashlib
import marshal

from controller.engine import ValidationOutcome
from controller.validators import _bind_validator


def _allow(attempt, context):
    return ValidationOutcome.allow()


def synthetic_validator(contract, callback=None):
    if getattr(contract, "validation_policy", None) is not None:
        raise ValueError("synthetic_validator_cannot_bind_reviewed_contract")
    callback = _allow if callback is None else callback
    code = getattr(callback, "__code__", None)
    if code is None:
        raise ValueError("synthetic_test_function_required")
    return _bind_validator(
        {"mode": "synthetic_test", "policy_id": "synthetic-test:" + contract.workflow_id,
         "policy_version": "1", "callback_module": callback.__module__,
         "callback_name": callback.__qualname__,
         "callback_sha256": hashlib.sha256(marshal.dumps(code)).hexdigest()},
        "test", callback, (contract.workflow_id, contract.version))
