"""Loopback protocol tests with a fake worker: no model, AWS or controller calls."""
import asyncio
from contextlib import redirect_stderr, redirect_stdout
from http.client import HTTPConnection
import importlib.util
import io
import json
from pathlib import Path
import threading
import unittest

PATH = Path(__file__).resolve().parents[1] / "agentcore_worker.py"
SPEC = importlib.util.spec_from_file_location("agentcore_worker", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
TOKEN = "synthetic_run_token_12345678901234567890"


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

        async def worker(url, token, **kwargs):
            self.calls.append((url, token, kwargs))
            return {"status": "completed", "usage": {"input_tokens": 1, "output_tokens": 2}}

        self.server = MODULE.WorkerServer(("127.0.0.1", 0), "https://controller.example.invalid", worker)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, path, body=None, *, raw=None, headers=None):
        client = HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            if body is not None:
                raw = json.dumps(body)
            client.request("GET" if raw is None else "POST", path, body=raw,
                           headers=headers or {"Content-Type": "application/json"})
            response = client.getresponse()
            return response.status, response.getheader("Content-Type"), json.loads(response.read())
        finally:
            client.close()

    def test_ping_exact_shape_and_stable_transition_timestamp(self):
        code, content_type, value = self.request("/ping")
        self.assertEqual((code, content_type), (200, "application/json"))
        self.assertEqual(set(value), {"status", "time_of_last_update"})
        self.assertEqual(value["status"], "Healthy")
        self.assertIs(type(value["time_of_last_update"]), int)
        self.assertEqual(self.request("/ping")[2], value)
        self.assertEqual(self.calls, [])

    def test_valid_invocation_uses_trusted_endpoint_and_scoped_input(self):
        code, _, value = self.request("/invocations", {"run_token": TOKEN, "memory": "untrusted", "max_turns": 2})
        self.assertEqual((code, value["status"]), (200, "completed"))
        self.assertEqual(self.calls, [("https://controller.example.invalid", TOKEN,
                                      {"memory": "untrusted", "max_turns": 2})])

    def test_authority_and_endpoint_overrides_rejected_before_worker(self):
        for field in ("controller_url", "url", "admin_token", "provider_key", "policy", "tenant_id"):
            with self.subTest(field=field):
                code, _, _ = self.request("/invocations", {"run_token": TOKEN, field: "forbidden"})
                self.assertEqual(code, 400)
        self.assertEqual(self.calls, [])

    def test_duplicate_keys_nonfinite_tokens_and_scope_limits_rejected(self):
        invalid = [
            '{"run_token":"' + TOKEN + '","run_token":"' + TOKEN + '"}',
            '{"run_token":"' + TOKEN + '","max_turns":NaN}',
            json.dumps({"run_token": TOKEN, "max_turns": True}),
            json.dumps({"run_token": TOKEN, "max_turns": 7}),
            json.dumps({"run_token": TOKEN, "memory": "x" * 2049}),
            json.dumps({"run_token": "bad\r\nheader"}),
            "{}", "[]",
        ]
        for raw in invalid:
            with self.subTest(raw_length=len(raw)):
                self.assertEqual(self.request("/invocations", raw=raw)[0], 400)
        self.assertEqual(self.calls, [])

    def test_wrong_content_type_and_oversize_rejected(self):
        self.assertEqual(self.request("/invocations", {"run_token": TOKEN},
                                      headers={"Content-Type": "text/plain"})[0], 400)
        self.assertEqual(self.request("/invocations", raw="x" * (MODULE.MAX_BODY + 1))[0], 400)
        self.assertEqual(self.calls, [])

    def test_busy_rejects_overlap_and_ping_remains_responsive(self):
        entered, release = threading.Event(), threading.Event()

        async def worker(*args, **kwargs):
            entered.set()
            await asyncio.to_thread(release.wait, 2)
            return {"status": "completed"}

        self.server.worker = worker
        first_result = []
        first = threading.Thread(target=lambda: first_result.append(
            self.request("/invocations", {"run_token": TOKEN})))
        first.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertEqual(self.request("/ping")[2]["status"], "HealthyBusy")
            self.assertEqual(self.request("/invocations", {"run_token": TOKEN})[0], 429)
        finally:
            release.set()
            first.join(timeout=3)
        self.assertEqual(first_result[0][0], 200)
        self.assertEqual(self.request("/ping")[2]["status"], "Healthy")

    def test_deadline_keeps_outcome_unknown_and_does_not_retry(self):
        attempts = []

        async def worker(*args, **kwargs):
            attempts.append(True)
            await asyncio.sleep(1)

        self.server.worker = worker
        self.server.invocation_seconds = 0.02
        code, _, value = self.request("/invocations", {"run_token": TOKEN})
        self.assertEqual((code, value["status"]), (200, "held"))
        self.assertTrue(value["unknown_model_outcome"])
        self.assertEqual(len(attempts), 1)

    def test_token_and_exception_details_never_logged_or_returned(self):
        async def echo(*args, **kwargs):
            return {"status": "completed", "final_output": TOKEN}

        async def fail(*args, **kwargs):
            raise RuntimeError("sensitive " + TOKEN)

        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            self.server.worker = echo
            self.assertNotIn(TOKEN, json.dumps(self.request("/invocations", {"run_token": TOKEN})[2]))
            self.server.worker = fail
            response = self.request("/invocations", {"run_token": TOKEN})
            self.assertEqual(response[0], 503)
            self.assertNotIn(TOKEN, json.dumps(response[2]))
        self.assertEqual(output.getvalue(), "")

    def test_routes_are_exact_and_do_not_echo_untrusted_query(self):
        for path in ("/ping?token=" + TOKEN, "/invocations?x=1", "/jobs", "/stop"):
            code, _, value = self.request(path)
            self.assertEqual(code, 404)
            self.assertNotIn(TOKEN, json.dumps(value))

    def test_runtime_controller_url_requires_https(self):
        for url in (None, "http://127.0.0.1:8080", "http://controller.internal",
                    "https://user:password@controller.internal", "https://controller.internal/path",
                    "https://controller.internal?override=1", "https://controller.internal:invalid"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                MODULE.controller_endpoint(url)


if __name__ == "__main__":
    unittest.main()
