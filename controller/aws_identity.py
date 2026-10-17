"""Closed STS identity demonstration through the existing durable authority.

This trusted receiver accepts one read-only operation. It is an integration
proof, not an IAM boundary: GetCallerIdentity itself requires no IAM permission.
The agent never receives cloud credentials or selects an SDK callback/endpoint.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
import time

from .durable import DurableAuthority, DurableError, DurableResult, _plain
from .engine import Attempt, Binding, Capability, Contract, Limits, ValidationOutcome
from .validators import _bind_validator

ACTION = "sts.GetCallerIdentity"
MAX_BRIDGE_BYTES = 4096
RECEIPT_FIELDS = frozenset({"schema_version", "request_nonce", "account_matches",
                            "principal_sha256", "request_id_sha256", "http_status",
                            "source", "api_call_status"})


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _hex(value, size=64):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(size) + "}", value) is not None


@dataclass(frozen=True)
class IdentityConfig:
    expected_account: str
    region: str
    expected_principal_sha256: str

    def __post_init__(self):
        if (type(self.expected_account) is not str
                or re.fullmatch(r"[0-9]{12}", self.expected_account) is None
                or type(self.region) is not str
                or re.fullmatch(r"(?:us|eu|ap|af|ca|me|sa|il|mx)-(?:gov-)?[a-z]+-[1-9][0-9]?", self.region) is None
                or not _hex(self.expected_principal_sha256)):
            raise ValueError("invalid_aws_identity_config")

    @property
    def context(self):
        return {"account_id": self.expected_account, "region": self.region,
                "expected_principal_sha256": self.expected_principal_sha256}


def build_contract(config: IdentityConfig):
    if type(config) is not IdentityConfig:
        raise ValueError("trusted_identity_config_required")
    return Contract(
        workflow_id="aws-identity-demo", version="1",
        purpose="Verify one explicitly pinned AWS identity through the controller.",
        capabilities=frozenset({Capability("identity", ACTION,
                                           "aws-account:" + config.expected_account, "worker")}),
        required_context={"identity": ("account_id", "region", "expected_principal_sha256")},
        limits=Limits(budget_calls=1, input_bytes=4096, runtime_seconds=180,
                      max_children=0, max_depth=0),
        allowed_principals=frozenset({("aws-demo", "operator")}),
        payload_fields={ACTION: ()}, handoff_actions=frozenset(),
        step_dependencies={"identity": ()}, validation_policy="aws-identity-demo:1",
    )


def _validator(config, contract):
    expected = config.context

    def validate(attempt, context):
        if dict(context) != expected:
            return ValidationOutcome.deny("identity_context_mismatch")
        return ValidationOutcome.allow()

    return _bind_validator(
        {"mode": "reviewed", "policy_id": contract.validation_policy,
         "policy_version": "1", "definition_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         "configuration_sha256": sha256(json.dumps(expected, sort_keys=True))},
        "controller", validate, (contract.workflow_id, contract.version),
    )


def private_directory(path):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("unsafe_private_directory")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.getuid()):
        raise ValueError("unsafe_private_directory")
    return path


def write_private_json(path, value):
    encoded = json.dumps(value, sort_keys=True, allow_nan=False).encode()
    if len(encoded) > MAX_BRIDGE_BYTES:
        raise ValueError("bridge_input_limit")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def read_private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid()
                or info.st_size > MAX_BRIDGE_BYTES):
            raise ValueError("unsafe_bridge_file")
        data = stream.read(MAX_BRIDGE_BYTES + 1)
        if len(data) > MAX_BRIDGE_BYTES:
            raise ValueError("bridge_input_limit")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_bridge_field")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_bridge_json")))


class FileIdentityBridge:
    """One-shot operator bridge. Its response must be obtained after dispatch.

    The operator polls request.json, calls STS once and atomically publishes the
    closed sanitized receipt.json. A request never contains bearer credentials.
    """

    def __init__(self, directory):
        self.directory = private_directory(directory)
        if any((self.directory / name).exists() or (self.directory / name).is_symlink()
               for name in ("request.json", "receipt.json")):
            raise ValueError("identity_bridge_requires_fresh_files")

    def __call__(self, request):
        write_private_json(self.directory / "request.json", request)
        # This demo's operator bridge crosses an application-tool boundary.
        # Production ControllerClient timeouts remain unchanged.
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                return read_private_json(self.directory / "receipt.json")
            except FileNotFoundError:
                time.sleep(.01)
        raise TimeoutError("identity_bridge_timeout")


class AWSIdentityController:
    """Trusted, closed receiver; adapters are supplied only by trusted Python setup."""

    def __init__(self, directory, config: IdentityConfig, adapter):
        if type(config) is not IdentityConfig or not callable(adapter):
            raise ValueError("trusted_identity_configuration_required")
        self.directory = private_directory(directory)
        self.config, self.contract = config, build_contract(config)
        self.validator = _validator(config, self.contract)
        self._adapter = adapter
        self._lock = threading.RLock()
        self.instance_id = secrets.token_hex(16)
        self.events = []
        self.adapter_calls = 0
        self.authority = DurableAuthority(self.directory / "authority.sqlite", self.contract,
                                          self.validator, prices={ACTION: 0}, budget_microusd=0).activate()
        for path in (self.authority.path, self.authority.fence_path):
            os.chmod(path, 0o600)
        self.core = self.authority
        self.context = config.context
        self.capabilities = self.contract.capabilities
        self.token = self.authority.admit(Binding("aws-demo", "operator", "identity-session", "root"),
                                          self.context)
        self.run_id = self.authority.snapshot(self.token).run_id
        self._record("job_created")

    def observation_context(self):
        return {"run_id_hash": sha256(self.run_id), "config_pin": self.authority.config_pin,
                "policy_pin": self.validator.policy_pin, "authority_epoch": self.authority.epoch,
                "controller_instance_id": self.instance_id}

    def _record(self, event, operation_id=None, **codes):
        value = {"schema_version": 1, "source": "controller", "event_id": len(self.events) + 1,
                 "at": time.time(), "event": event, **self.observation_context(), **codes}
        if operation_id is not None:
            value["operation_id_hash"] = sha256(operation_id)
        self.events.append(value)

    def proposal(self, operation_id="identity-allowed", **changes):
        return {"operation_id": operation_id, "step": "identity", "action": ACTION,
                "resource": "aws-account:" + self.config.expected_account,
                "recipient": "worker", "payload": {}, **changes}

    def _authenticated(self, token):
        return type(token) is str and secrets.compare_digest(token, self.token)

    def reserve(self, token, attempt):
        if not self._authenticated(token):
            return DurableResult("denied", "unknown_credential")
        try:
            if type(attempt) is not dict or set(attempt) != {
                    "operation_id", "step", "action", "resource", "recipient", "payload"}:
                raise ValueError("malformed_attempt")
            checked = Attempt(**attempt)
        except (TypeError, ValueError):
            return DurableResult("denied", "malformed_attempt")
        self._record("action_proposed", checked.operation_id)
        result = self.authority.reserve(token, checked)
        self._record("decision", checked.operation_id, status=result.status, reason=result.reason)
        return result

    def _valid_receipt(self, value, nonce):
        return (type(value) is dict and set(value) == RECEIPT_FIELDS
                and type(value["schema_version"]) is int and value["schema_version"] == 1
                and value["request_nonce"] == nonce
                and value["account_matches"] is True
                and value["source"] == "aws_mcp" and value["api_call_status"] == "success"
                and value["principal_sha256"] == self.config.expected_principal_sha256
                and (value["request_id_sha256"] is None or _hex(value["request_id_sha256"]))
                and (value["http_status"] is None
                     or type(value["http_status"]) is int and value["http_status"] == 200))

    def execute(self, token, ticket):
        with self._lock:
            if not self._authenticated(token) or type(ticket) is not str:
                return DurableResult("denied", "unknown_credential")
            # A bearer ticket alone cannot choose a different admitted run.
            with sqlite3.connect(self.authority.path) as conn:
                row = conn.execute("SELECT run_id FROM operations WHERE ticket=?", (ticket,)).fetchone()
            if row is None:
                return DurableResult("denied", "unknown_ticket")
            if row[0] != self.run_id:
                return DurableResult("denied", "ticket_binding_mismatch")
            claimed = self.authority.claim(ticket, allowed_recipients={"worker"}, allowed_actions={ACTION})
            if claimed.status != "allowed" or claimed.dispatch is None:
                return claimed
            dispatch = claimed.dispatch
            self._record("tool_started", dispatch.attempt.operation_id)
            nonce = secrets.token_hex(16)
            request = {"schema_version": 1, "service": "sts", "operation": "GetCallerIdentity",
                       "region": self.config.region, "params": {}, "request_nonce": nonce,
                       "run_id_hash": sha256(dispatch.run_id),
                       "operation_id_hash": sha256(dispatch.attempt.operation_id),
                       "config_pin": self.authority.config_pin}
            try:
                self.adapter_calls += 1
                receipt = self._adapter(request)
                if not self._valid_receipt(receipt, nonce):
                    raise ValueError("identity_receipt_invalid")
            except Exception:
                # Exception text may contain provider/account data. Never retain it.
                self._record("tool_finished", dispatch.attempt.operation_id, status="held", reason="operation_unknown")
                return self.authority.mark_unknown(ticket)
            sanitized = {key: receipt[key] for key in (
                "account_matches", "principal_sha256", "request_id_sha256", "http_status",
                "source", "api_call_status")}
            settled = self.authority.settle(ticket, sanitized, 0)
            self._record("tool_finished", dispatch.attempt.operation_id,
                         status=settled.status, reason=settled.reason)
            if settled.status != "allowed":
                return settled
            released = self.authority.release_result(ticket, allowed_recipients={"worker"}, allowed_actions={ACTION})
            self._record("result_release", dispatch.attempt.operation_id,
                         status=released.status, reason=released.reason)
            return released

    def act(self, token, attempt):
        with self._lock:
            result = self.reserve(token, attempt)
            replayed = result.replayed
            if result.status == "reserved":
                result = self.execute(token, result.ticket)
            elif result.status == "allowed" and result.replayed:
                result = self.authority.release_result(result.ticket, allowed_recipients={"worker"}, allowed_actions={ACTION})
            value = {"status": result.status, "reason": result.reason, "replayed": replayed or result.replayed,
                     "trace_context": self.observation_context()}
            if result.status == "allowed" and result.receipt is not None:
                value["receipt"] = _plain(result.receipt)
            return value

    def snapshot(self):
        return self.authority.snapshot(self.token)

    def stop(self):
        self.authority.stop_root(self.token)

    def close(self):
        # SQLite uses per-operation connections. Do not delete uncertain state.
        pass
