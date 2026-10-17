"""Run a separate SDK agent against one operator-bridged AWS STS receiver.

Only the trusted operator performs the AWS API call, after the durable claim.
This local integration proof does not deploy a worker in AWS or establish IAM
isolation. Uncertain private authority state is retained for operator review.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys

from controller.aws_identity import (AWSIdentityController, FileIdentityBridge, IdentityConfig,
                                     private_directory, sha256, write_private_json)
from demo.contract import _safe_agent_trace, _safe_controller_events
from demo.local import PROJECT, process_environment
from demo.run import check
from integration.process import run_sdk_process


def demonstrate(bridge_directory, config, output_directory, *, adapter=None):
    bridge_directory = private_directory(bridge_directory)
    output_directory = private_directory(output_directory)
    controller = AWSIdentityController(bridge_directory / "state", config,
                                        adapter if adapter is not None else FileIdentityBridge(bridge_directory))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _reply(self, code, value):
            data = json.dumps(value, allow_nan=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self):
            value = self.headers.get("Authorization", "")
            return secrets.compare_digest(value, "Bearer " + controller.token)

        def do_POST(self):
            if not self._authorized():
                self._reply(403, {"status": "denied", "reason": "unknown_credential"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if self.path != "/act" or not 0 < length <= 4096:
                    raise ValueError("invalid_request")
                body = json.loads(self.rfile.read(length))
                if type(body) is not dict or set(body) != {"attempt"}:
                    raise ValueError("invalid_request")
                self._reply(200, controller.act(controller.token, body["attempt"]))
            except (TypeError, ValueError, OSError):
                self._reply(400, {"status": "denied", "reason": "malformed_attempt"})

        def do_GET(self):
            if not self._authorized():
                self._reply(403, {"status": "denied", "reason": "unknown_credential"})
            elif self.path == "/snapshot":
                self._reply(200, {"trace_context": controller.observation_context()})
            else:
                self._reply(404, {"status": "denied", "reason": "unknown_endpoint"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        allowed = controller.proposal()
        denied = controller.proposal("identity-outside-scope", action="sts.AssumeRole")
        plan_path = bridge_directory / "plan.json"
        write_private_json(plan_path, [allowed, denied])
        env = {**process_environment(), "CONTROLLER_WORKER_TOKEN": controller.token}
        result = run_sdk_process(
            [sys.executable, "-m", "demo.aws_identity_agent", "--url",
             "http://127.0.0.1:" + str(server.server_port), "--plan", str(plan_path)],
            cwd=PROJECT, env=env, ready_file=bridge_directory / "agent-ready.json", timeout=75)
        try:
            worker = json.loads(result.stdout)
        except ValueError:
            raise RuntimeError("sdk_identity_agent_failed") from None
        checks = []
        def prove(name, condition):
            check(condition, name)
            checks.append({"check": name, "passed": True})
        prove("closed_contract_one_identity_operation", len(controller.capabilities) == 1
              and controller.contract.limits.budget_calls == 1)
        prove("sdk_agent_is_separate_process", worker.get("worker_pid") != os.getpid()
              and type(worker.get("worker_pid")) is int)
        permitted = [event for event in controller.events
                     if event.get("operation_id_hash") == sha256(allowed["operation_id"])]
        forbidden = [event for event in controller.events
                     if event.get("operation_id_hash") == sha256(denied["operation_id"])]
        prove("claimed_identity_executed_once", controller.adapter_calls == 1
              and sum(event["event"] == "tool_started" for event in permitted) == 1)
        prove("matching_identity_receipt_released", len(worker.get("results", [])) == 1
              and worker["results"][0].get("status") == "allowed"
              and worker["results"][0].get("receipt", {}).get("account_matches") is True
              and any(event["event"] == "result_release" and event.get("status") == "allowed"
                      for event in permitted))
        prove("out_of_scope_action_denied", worker.get("status") == "denied"
              and worker.get("reason") == "outside_scope" and result.returncode == 3
              and any(event["event"] == "decision" and event.get("reason") == "outside_scope"
                      for event in forbidden))
        prove("denied_action_never_dispatched", bool(forbidden)
              and not any(event["event"] in {"tool_started", "tool_finished", "result_release"}
                          for event in forbidden))
        agent_trace = _safe_agent_trace(worker.get("agent_trace"))
        controller_trace = _safe_controller_events(controller.events)
        prove("agent_controller_traces_correlated", not agent_trace["truncated"]
              and not agent_trace["unavailable"] and agent_trace["dropped_events"] == 0
              and all(agent_trace[key] == controller.observation_context()[key]
                      for key in controller.observation_context())
              and all(any(event.get("operation_id_hash") == sha256(operation["operation_id"])
                          and event["event"] == "action_result" for event in agent_trace["events"])
                      for operation in (allowed, denied)))
        snapshot = controller.snapshot()
        prove("settled_no_unknown_operation", snapshot.calls_used == 1
              and not snapshot.unknown_operations and snapshot.reserved_microusd == 0)
        report = {"schema_version": 1, "mode": "operator_bridge_aws_identity",
                  "evidence_source": ("injected_test_adapter" if adapter is not None
                                      else "operator_aws_mcp_bridge"),
                  "aws_operation": "sts.GetCallerIdentity", "aws_mutations": 0,
                  "live_model_calls": 0, "adapter_requests": controller.adapter_calls,
                  "checks": checks,
                  "identity_receipt": worker["results"][0]["receipt"],
                  "observability": {"schema_version": 1,
                                    "join_keys": ["run_id_hash", "operation_id_hash"],
                                    "authority_source": "controller",
                                    "timing_note": "Each source retains its own event order; cross-process clocks are not ordered.",
                                    "agent_trace": agent_trace,
                                    "controller_trace": {"source": "controller", "events": controller_trace}},
                  "limits": {"iam_isolation_proven": False, "aws_worker_deployment_proven": False,
                             "sts_requires_iam_permission": False,
                             "operator_bridge_receipt_is_trusted": True}}
        # Report is sanitized but private by default; state stays outside release.
        report_path = output_directory / "contract-report.json"
        # Large traces exceed the bridge JSON bound, so use a separate bounded writer.
        encoded = json.dumps(report, indent=2, allow_nan=False).encode()
        check(len(encoded) <= 65536, "identity_report_limit")
        fd = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
        return report
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        controller.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge-dir", type=Path, required=True)
    parser.add_argument("--expected-account", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--expected-principal-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = IdentityConfig(args.expected_account, args.region, args.expected_principal_sha256)
        report = demonstrate(args.bridge_dir, config, args.output_dir)
    except Exception:
        # All detailed provider/SDK errors stay out of stdout; uncertain state remains.
        print(json.dumps({"status": "held", "reason": "aws_identity_demo_incomplete",
                          "private_state_retained": True}))
        return 2
    print(json.dumps({"status": "passed", "checks": len(report["checks"]),
                      "adapter_requests": report["adapter_requests"], "aws_mutations": 0,
                      "report": str(args.output_dir / "contract-report.json")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
