"""Bounded custom AgentCore HTTP transport; controller remains the authority.

The AgentCore platform must authenticate inbound callers. This plain HTTP
container endpoint is not standalone authentication or a public web service.
Only trusted runtime configuration may choose the controller's HTTPS endpoint.
"""
from __future__ import annotations

import argparse
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import threading
import time
from urllib.parse import urlsplit

MAX_BODY = 8192
MAX_RESPONSE = 65536
MAX_CONNECTIONS = 16
DEFAULT_INVOCATION_SECONDS = 180


def controller_endpoint(value):
    if not isinstance(value, str):
        raise ValueError("trusted_https_controller_url_required")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            or any(character.isspace() for character in value)):
        raise ValueError("trusted_https_controller_url_required")
    try:
        parsed.port
    except ValueError:
        raise ValueError("trusted_https_controller_url_required") from None
    return value.rstrip("/")


def invocation(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("invalid_invocation")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("invalid_invocation")

    document = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
    if (type(document) is not dict or "run_token" not in document
            or set(document) - {"run_token", "memory", "max_turns"}):
        raise ValueError("invalid_invocation")
    token = document["run_token"]
    memory = document.get("memory", "")
    turns = document.get("max_turns", 6)
    if (not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24,512}", token)
            or not isinstance(memory, str) or len(memory.encode("utf-8")) > 2048
            or type(turns) is not int or not 1 <= turns <= 6):
        raise ValueError("invalid_invocation")
    return token, memory, turns


class WorkerServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = MAX_CONNECTIONS

    def __init__(self, address, url, worker, *, invocation_seconds=DEFAULT_INVOCATION_SECONDS):
        self.controller_url = controller_endpoint(url)
        if type(invocation_seconds) not in (int, float) or not 0 < invocation_seconds <= 180:
            raise ValueError("invalid_invocation_deadline")
        self.worker = worker
        self.invocation_seconds = invocation_seconds
        self.invocation_lock = threading.Lock()
        self.connections = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.status_lock = threading.Lock()
        self.status = "Healthy"
        self.status_changed_at = int(time.time())
        super().__init__(address, WorkerHandler)

    def set_busy(self, busy):
        with self.status_lock:
            status = "HealthyBusy" if busy else "Healthy"
            if status != self.status:
                self.status, self.status_changed_at = status, int(time.time())

    def health(self):
        with self.status_lock:
            return {"status": self.status, "time_of_last_update": self.status_changed_at}

    def process_request(self, request, client_address):
        if not self.connections.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connections.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connections.release()

    def handle_error(self, request, client_address):
        # Never print request details or exception text containing bearer data.
        pass


class WorkerHandler(BaseHTTPRequestHandler):
    server_version = "AgentControllerWorker/1"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_args):
        pass

    def send_error(self, code, message=None, explain=None):
        self.respond(code, {"status": "blocked", "reason": "http_request_rejected"})

    def respond(self, code, value, *, token=None):
        trace_omitted = False
        try:
            raw = json.dumps(value, separators=(",", ":"), allow_nan=False)
            if token:
                raw = raw.replace(token, "[redacted-run-token]")
            payload = raw.encode("utf-8")
            if len(payload) > MAX_RESPONSE and type(value) is dict and "agent_trace" in value:
                # Optional telemetry must not turn an otherwise valid business
                # outcome into an unknown result at the fixed response limit.
                raw = json.dumps({key: item for key, item in value.items() if key != "agent_trace"},
                                 separators=(",", ":"), allow_nan=False)
                if token:
                    raw = raw.replace(token, "[redacted-run-token]")
                payload = raw.encode("utf-8")
                trace_omitted = True
            if len(payload) > MAX_RESPONSE:
                raise ValueError
        except (ValueError, TypeError, RecursionError):
            code, payload = 503, b'{"status":"held","reason":"worker_result_invalid","unknown_model_outcome":true}'
        self.close_connection = True
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        if trace_omitted:
            self.send_header("X-Agent-Trace-Status", "omitted_response_limit")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (OSError, TimeoutError):
            pass  # Caller disconnects do not prove controller/provider cancellation.

    def do_GET(self):
        if self.path != "/ping":
            self.respond(404, {"status": "blocked", "reason": "unknown_route"})
            return
        self.respond(200, self.server.health())

    def do_POST(self):
        if self.path != "/invocations":
            self.respond(404, {"status": "blocked", "reason": "unknown_route"})
            return
        try:
            if (self.headers.get_all("Transfer-Encoding")
                    or len(self.headers.get_all("Content-Length", [])) != 1
                    or len(self.headers.get_all("Content-Type", [])) != 1
                    or self.headers["Content-Type"].split(";", 1)[0].strip().lower() != "application/json"):
                raise ValueError
            size = int(self.headers["Content-Length"])
            if not 0 < size <= MAX_BODY:
                raise ValueError
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError
            token, memory, turns = invocation(raw)
        except (ValueError, TypeError, UnicodeError, RecursionError, OSError):
            self.respond(400, {"status": "blocked", "reason": "invalid_invocation"})
            return
        if not self.server.invocation_lock.acquire(blocking=False):
            self.respond(429, {"status": "blocked", "reason": "worker_busy"})
            return
        self.server.set_busy(True)
        try:
            async def run():
                return await asyncio.wait_for(
                    self.server.worker(self.server.controller_url, token, memory=memory, max_turns=turns),
                    timeout=self.server.invocation_seconds)
            try:
                value = asyncio.run(run())
                if type(value) is not dict:
                    raise ValueError
                self.respond(200, value, token=token)
            except TimeoutError:
                self.respond(200, {"status": "held", "reason": "worker_deadline_exceeded",
                                   "unknown_model_outcome": True})
            except Exception:
                self.respond(503, {"status": "held", "reason": "worker_failed",
                                   "unknown_model_outcome": True})
        finally:
            self.server.set_busy(False)
            self.server.invocation_lock.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    try:
        url = controller_endpoint(os.environ.get("CONTROLLER_URL"))
        from integration.live_worker import _has_privileged_credentials, run_worker
        if _has_privileged_credentials():
            raise ValueError("worker_privileged_credential_present")
        server = WorkerServer((args.host, args.port), url, run_worker)
    except (ImportError, OSError, ValueError):
        print(json.dumps({"status": "blocked", "reason": "invalid_worker_runtime_configuration"}))
        return 2
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
