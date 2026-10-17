"""The optional exporter fails safely and never sends during preview or validation."""
import io
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler

import pytest

from integration import braintrust_export as export
from integration.trace_export import ExportError, build_export


PROJECT = "5f372376-301b-423a-bd16-ef26c0c64fb7"
KEY = "synthetic-private-export-key-never-print"
CANARY = "private-input-response-or-path-never-print"


def report():
    bindings = {"run_id_hash": "a" * 64, "config_pin": "b" * 64,
                "policy_pin": "c" * 64, "controller_instance_id": "d" * 32,
                "authority_epoch": 1}
    operation = "e" * 64
    return {"observability": {"schema_version": 1, "agent_trace": {
        "schema_version": 1, "source": "agent_sdk", "trust": "agent_reported_diagnostic",
        **bindings, "truncated": False, "unavailable": False, "dropped_events": 0,
        "events": [{"seq": 1, "elapsed_ms": 0, "event": "action_proposed",
                    "operation_id_hash": operation},
                   {"seq": 2, "elapsed_ms": 1, "event": "action_result",
                    "operation_id_hash": operation, "status": "denied", "reason": "outside_scope"}],
    }, "controller_trace": {"source": "controller", "events": [
        {"source": "controller", "event_id": 1, "at": 1000, "event": "action_proposed",
         **bindings, "operation_id_hash": operation},
        {"source": "controller", "event_id": 2, "at": 1001, "event": "decision",
         **bindings, "operation_id_hash": operation, "status": "denied", "reason": "outside_scope"},
    ]}}}


def write_report(tmp_path, value=None):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report() if value is None else value))
    return path


def assert_fixed_error(error):
    assert re.fullmatch(r"[a-z][a-z0-9_]{0,80}", str(error))
    assert CANARY not in str(error)


class Response:
    def __init__(self, body, status=200):
        self.body = io.BytesIO(body)
        self.status = status
        self.read_sizes = []
        self.closed = False

    def read(self, count=-1):
        self.read_sizes.append(count)
        return self.body.read(count)

    def getcode(self):
        return self.status

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class Opener:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    def open(self, request, *, timeout):
        self.calls.append((request, timeout))
        if self.error is not None:
            raise self.error
        return self.response


def delivery_payload():
    rows = build_export(report(), PROJECT)["events"]
    return json.dumps({"events": rows}, separators=(",", ":")).encode(), [row["id"] for row in rows]


def forbid(*_args, **_kwargs):
    pytest.fail("preview or invalid input attempted credential access, a process, or network I/O")


def test_report_load_round_trips_valid_input(tmp_path):
    assert export.load_report(write_report(tmp_path)) == report()


@pytest.mark.parametrize("raw", [
    b'{"observability":1,"observability":2}',
    b'{"observability":{"schema_version":1,"schema_version":1}}',
    b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}',
    b'\xff', b'[]', b'null', b'"' + CANARY.encode() + b'"',
    b'{"x":' * 34 + b'0' + b'}' * 34,
    b'{"observability":1} trailing-' + CANARY.encode(),
    b' ' * (256 * 1024 + 1),
])
def test_bad_json_has_a_fixed_error_without_input_contents(tmp_path, raw):
    path = tmp_path / CANARY
    path.write_bytes(raw)
    with pytest.raises(ExportError) as caught:
        export.load_report(path)
    assert_fixed_error(caught.value)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "hardlink", "missing"])
def test_only_single_link_regular_report_files_are_read(tmp_path, kind):
    source = write_report(tmp_path)
    path = tmp_path / CANARY
    if kind == "symlink":
        path.symlink_to(source)
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    elif kind == "hardlink":
        os.link(source, path)
    with pytest.raises(ExportError) as caught:
        export.load_report(path)
    assert_fixed_error(caught.value)


def test_preview_file_is_private_and_never_overwritten(tmp_path):
    path = tmp_path / "preview.json"
    payload = b'{"events":[]}'
    export.write_preview(path, payload)
    assert path.read_bytes() == payload
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(ExportError) as caught:
        export.write_preview(path, b"replacement-" + CANARY.encode())
    assert_fixed_error(caught.value)
    assert path.read_bytes() == payload


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "missing_parent"])
def test_preview_does_not_follow_existing_paths_or_create_parent_directories(tmp_path, kind):
    target = tmp_path / "original"
    target.write_bytes(CANARY.encode())
    path = tmp_path / "preview.json"
    if kind == "symlink":
        path.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, path)
    elif kind == "directory":
        path.mkdir()
    else:
        path = tmp_path / "missing" / "preview.json"
    with pytest.raises(ExportError) as caught:
        export.write_preview(path, b'{"events":[]}')
    assert_fixed_error(caught.value)
    assert target.read_bytes() == CANARY.encode()
    assert not (tmp_path / "missing").exists()


def test_post_sends_once_to_fixed_tls_endpoint_and_checks_exact_acknowledgement():
    payload, identifiers = delivery_payload()
    response = Response(json.dumps({"row_ids": identifiers}).encode())
    opener = Opener(response)
    result = export._post_events(payload, PROJECT, KEY, opener=opener)
    assert len(opener.calls) == 1
    request, timeout = opener.calls[0]
    assert request.full_url == "https://api.braintrust.dev/v1/project_logs/" + PROJECT + "/insert"
    assert request.get_method() == "POST"
    assert request.data == payload
    assert request.get_header("Authorization") == "Bearer " + KEY
    assert request.get_header("Content-type") == "application/json"
    assert timeout == 5
    assert response.read_sizes and all(0 <= size <= 65537 for size in response.read_sizes)
    assert response.closed
    encoded = json.dumps(result)
    assert KEY not in encoded and "row_ids" not in encoded
    assert result == {"status": "sent", "reason": "acknowledged", "attempts": 1,
                      "delivery_unknown": False, "http_status": 200}


@pytest.mark.parametrize("body", [
    b'{"row_ids":[]}', b'{"row_ids":["wrong"]}', b'{}', b'[]',
    b'{"row_ids":null}', b'{"row_ids":[],"row_ids":[]}',
    b'{"row_ids":[],"extra":NaN}', b'\xff', b'x' * 65537,
])
def test_unconfirmed_or_invalid_ack_is_safe_and_never_retried(body):
    payload, _identifiers = delivery_payload()
    response = Response(body)
    opener = Opener(response)
    result = export._post_events(payload, PROJECT, KEY, opener=opener)
    assert len(opener.calls) == 1
    encoded = json.dumps(result)
    assert KEY not in encoded and CANARY not in encoded
    assert result["status"] == "unknown" and result["delivery_unknown"] is True


def test_acknowledgement_order_and_multiplicity_must_match_submitted_rows():
    payload, identifiers = delivery_payload()
    for changed in (list(reversed(identifiers)), identifiers[:-1], identifiers + identifiers[:1]):
        opener = Opener(Response(json.dumps({"row_ids": changed}).encode()))
        result = export._post_events(payload, PROJECT, KEY, opener=opener)
        assert result["status"] == "unknown" and result["delivery_unknown"] is True
        assert len(opener.calls) == 1


@pytest.mark.parametrize("status", [301, 302, 307, 308, 400, 401, 403, 429, 500])
def test_http_failures_keep_numeric_status_without_body_location_or_credentials(status):
    payload, _identifiers = delivery_payload()
    error = HTTPError("https://" + CANARY, status, "private-" + CANARY,
                      {"Location": "https://" + KEY}, io.BytesIO(CANARY.encode()))
    opener = Opener(error=error)
    result = export._post_events(payload, PROJECT, KEY, opener=opener)
    assert len(opener.calls) == 1
    encoded = json.dumps(result)
    assert CANARY not in encoded and KEY not in encoded
    assert status in result.values()
    assert result["status"] in {"rejected", "unknown"}


@pytest.mark.parametrize("error", [URLError(CANARY), TimeoutError(CANARY),
                                   OSError(CANARY), ssl.SSLError(CANARY)])
def test_transport_failures_are_safe_and_are_not_retried(error):
    payload, _identifiers = delivery_payload()
    opener = Opener(error=error)
    result = export._post_events(payload, PROJECT, KEY, opener=opener)
    assert len(opener.calls) == 1
    assert CANARY not in json.dumps(result) and KEY not in json.dumps(result)
    assert result["status"] == "unknown" and result["delivery_unknown"] is True


class CredentialGuard(dict):
    """Permit unrelated environment access while detecting exporter-key reads."""
    def __getitem__(self, key):
        if key == "BRAINTRUST_API_KEY":
            forbid()
        return super().__getitem__(key)

    def get(self, key, default=None):
        if key == "BRAINTRUST_API_KEY":
            forbid()
        return super().get(key, default)


def test_default_cli_is_offline_does_not_read_key_and_prints_only_projection(tmp_path, monkeypatch, capsys):
    value = report()
    value.update(prompt=CANARY, credential=KEY, scope={"record": CANARY})
    path = write_report(tmp_path, value)
    monkeypatch.setattr(export, "_deliver", forbid)
    monkeypatch.setattr(socket.socket, "connect", forbid)
    monkeypatch.setattr(socket, "create_connection", forbid)
    monkeypatch.setattr(export.os, "environ", CredentialGuard(os.environ))
    assert export.main(["--report", str(path), "--project-id", PROJECT]) == 0
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["events"] and output["project_id"] == PROJECT
    assert not captured.err
    assert CANARY not in captured.out and KEY not in captured.out
    assert set(tmp_path.iterdir()) == {path}


def test_output_cli_writes_private_projection_and_prints_no_rows(tmp_path, monkeypatch, capsys):
    path = write_report(tmp_path)
    destination = tmp_path / "preview.json"
    monkeypatch.setattr(export, "send_report", forbid)
    monkeypatch.setattr(export.os, "environ", CredentialGuard(os.environ))
    assert export.main(["--report", str(path), "--project-id", PROJECT,
                        "--output", str(destination)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert "events" not in summary
    assert json.loads(destination.read_bytes())["events"]
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


@pytest.mark.parametrize("kind", ["json", "schema", "project"])
def test_cli_validates_input_before_reading_key_or_starting_delivery(tmp_path, monkeypatch, capsys, kind):
    path = write_report(tmp_path)
    project = PROJECT
    if kind == "json":
        path.write_text('{"broken":' + CANARY)
    elif kind == "schema":
        malformed = report()
        malformed["observability"]["agent_trace"]["events"][0]["event"] = CANARY
        path.write_text(json.dumps(malformed))
    else:
        project = CANARY
    monkeypatch.setattr(export, "send_report", forbid)
    monkeypatch.setattr(export.os, "environ", CredentialGuard(os.environ))
    assert export.main(["--report", str(path), "--project-id", project, "--send"]) == 2
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err and KEY not in captured.out + captured.err


@pytest.mark.parametrize("credential", [None, "", "line\nbreak-" + CANARY,
                                        "line\rbreak-" + CANARY, " " + KEY, KEY + " "])
def test_send_requires_valid_operator_key_without_printing_it(tmp_path, monkeypatch, capsys, credential):
    path = write_report(tmp_path)
    monkeypatch.setattr(export, "_deliver", forbid)
    if credential is None:
        monkeypatch.delenv("BRAINTRUST_API_KEY", raising=False)
    else:
        monkeypatch.setenv("BRAINTRUST_API_KEY", credential)
    assert export.main(["--report", str(path), "--project-id", PROJECT, "--send"]) == 2
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err and KEY not in captured.out + captured.err


def test_send_report_validates_before_creating_delivery_process(monkeypatch):
    def unexpected(*_args, **_kwargs):
        pytest.fail("invalid input started the delivery process")
    monkeypatch.setattr(export, "_deliver", unexpected)
    malformed = report()
    malformed["observability"]["agent_trace"]["events"][0]["reason"] = CANARY
    with pytest.raises(ExportError) as caught:
        export.send_report(malformed, PROJECT, KEY)
    assert_fixed_error(caught.value)


def test_default_transport_verifies_tls_and_installs_credential_preserving_redirect_refusal(monkeypatch):
    payload, identifiers = delivery_payload()
    opener = Opener(Response(json.dumps({"row_ids": identifiers}).encode()))
    handlers = []

    def build(*values):
        handlers.extend(values)
        return opener

    monkeypatch.setattr(export, "build_opener", build)
    result = export._post_events(payload, PROJECT, KEY)
    assert result["status"] == "sent"
    https = next(handler for handler in handlers if isinstance(handler, HTTPSHandler))
    assert https._context.verify_mode == ssl.CERT_REQUIRED
    assert https._context.check_hostname is True
    redirect = next(handler for handler in handlers if isinstance(handler, export.NoRedirect))
    request = opener.calls[0][0]
    for status in (301, 302, 303, 307, 308):
        assert redirect.redirect_request(request, None, status, CANARY,
                                         {"Location": "https://" + CANARY},
                                         "https://" + CANARY) is None
    assert len(opener.calls) == 1


def test_send_report_passes_only_sanitized_events_to_delivery(monkeypatch):
    value = report()
    value.update(prompt=CANARY, credential=KEY, project_id=CANARY,
                 endpoint="https://" + CANARY, events=[{"input": CANARY}])
    calls = []

    def deliver(payload, project, key):
        calls.append((payload, project, key))
        return {"status": "sent", "reason": "acknowledged", "attempts": 1,
                "delivery_unknown": False, "http_status": 200}

    monkeypatch.setattr(export, "_deliver", deliver)
    result = export.send_report(value, PROJECT, KEY)
    assert len(calls) == 1
    payload, project, key = calls[0]
    assert project == PROJECT and key == KEY
    assert CANARY not in payload.decode() and KEY not in payload.decode()
    assert set(json.loads(payload)) == {"events"}
    assert result["status"] == "sent" and result["row_count"] == len(json.loads(payload)["events"])
    assert "events" not in result and "row_ids" not in result


@pytest.mark.parametrize("status,exit_code", [("sent", 0), ("unknown", 1), ("rejected", 1)])
def test_send_cli_prints_only_safe_delivery_summary(tmp_path, monkeypatch, capsys, status, exit_code):
    path = write_report(tmp_path)
    calls = []
    monkeypatch.setenv("BRAINTRUST_API_KEY", KEY)

    def deliver(payload, project, key):
        calls.append((payload, project, key))
        return {"status": status, "reason": "acknowledged" if status == "sent" else "transport_failed",
                "attempts": 1, "delivery_unknown": status == "unknown"}

    monkeypatch.setattr(export, "_deliver", deliver)
    assert export.main(["--report", str(path), "--project-id", PROJECT, "--send"]) == exit_code
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert len(calls) == 1 and result["status"] == status
    assert "events" not in result and "row_ids" not in result
    assert KEY not in captured.out + captured.err and CANARY not in captured.out + captured.err


class Connection:
    def __init__(self, *, ready=False, result=None, error=None):
        self.ready, self.result, self.error = ready, result, error
        self.closed, self.poll_calls = False, []

    def poll(self, timeout):
        self.poll_calls.append(timeout)
        return self.ready

    def recv(self):
        if self.error:
            raise self.error
        return self.result

    def close(self):
        self.closed = True


class Process:
    def __init__(self, *, stubborn=False, alive=True):
        self.stubborn, self.alive = stubborn, alive
        self.started = self.terminated = self.killed = self.closed = False
        self.join_calls = []

    def start(self):
        self.started = True

    def is_alive(self):
        return self.alive

    def terminate(self):
        self.terminated = True
        if not self.stubborn:
            self.alive = False

    def kill(self):
        self.killed = True
        self.alive = False

    def join(self, timeout=None):
        self.join_calls.append(timeout)

    def close(self):
        self.closed = True


def install_process(monkeypatch, receiver, *, stubborn=False, alive=True):
    sender = Connection()
    process = Process(stubborn=stubborn, alive=alive)
    calls = []

    class Context:
        def Pipe(self, *, duplex):
            assert duplex is False
            return receiver, sender

        def Process(self, *, target, args):
            assert target is export._send_child and args[0] is sender
            calls.append(args)
            return process

    def context(mode):
        assert mode == "spawn"
        return Context()

    monkeypatch.setattr(export.multiprocessing, "get_context", context)
    return sender, process, calls


@pytest.mark.parametrize("stubborn", [False, True])
def test_delivery_deadline_terminates_reaps_and_closes_child_without_retry(monkeypatch, stubborn):
    receiver = Connection()
    sender, process, calls = install_process(monkeypatch, receiver, stubborn=stubborn)
    payload, _identifiers = delivery_payload()
    result = export._deliver(payload, PROJECT, KEY)
    assert result == {"status": "unknown", "reason": "delivery_deadline_exceeded",
                      "attempts": 1, "delivery_unknown": True}
    assert receiver.poll_calls == [15]
    assert len(calls) == 1 and process.started and process.terminated
    assert process.killed is stubborn and process.join_calls == ([1, None] if stubborn else [1])
    assert sender.closed and receiver.closed and process.closed and not process.alive
    assert KEY not in json.dumps(result)


@pytest.mark.parametrize("error", [EOFError(CANARY), OSError(CANARY)])
def test_child_channel_failure_remains_unknown_and_reaps_child(monkeypatch, error):
    receiver = Connection(ready=True, error=error)
    sender, process, calls = install_process(monkeypatch, receiver)
    payload, _identifiers = delivery_payload()
    result = export._deliver(payload, PROJECT, KEY)
    assert len(calls) == 1 and result["status"] == "unknown"
    assert result["delivery_unknown"] is True and result["reason"] == "exporter_unavailable"
    assert process.terminated and process.closed and sender.closed and receiver.closed
    assert CANARY not in json.dumps(result) and KEY not in json.dumps(result)


def _stall_spawned_exporter(connection, payload, _project_id, _api_key):
    """An inert, kill-resistant child exercises cleanup without any network I/O."""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    # A final independent bound prevents an orphan if the implementation regresses.
    signal.alarm(4)
    path = Path(payload.decode())
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, str(os.getpid()).encode())
    finally:
        os.close(descriptor)
    signal.pause()


def test_real_spawned_exporter_deadline_kills_and_reaps_stalled_child(tmp_path, monkeypatch):
    pid_path = tmp_path / "exporter.pid"
    monkeypatch.setattr(export, "_send_child", _stall_spawned_exporter)
    monkeypatch.setattr(export, "DELIVERY_TIMEOUT_SECONDS", 1)
    started = time.monotonic()
    try:
        result = export._deliver(str(pid_path).encode(), PROJECT, KEY)
        elapsed = time.monotonic() - started
        assert pid_path.exists(), "spawned exporter did not reach its inert test target"
        pid = int(pid_path.read_text())
        assert pid != os.getpid()
        assert result == {"status": "unknown", "reason": "delivery_deadline_exceeded",
                          "attempts": 1, "delivery_unknown": True}
        assert 1 <= elapsed < 4
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
        assert KEY not in json.dumps(result) and CANARY not in json.dumps(result)
    finally:
        # Keep this test self-cleaning even if a future cleanup assertion fails.
        if pid_path.exists():
            pid = int(pid_path.read_text())
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
