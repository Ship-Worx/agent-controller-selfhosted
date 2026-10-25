"""Scripted SDK agent for the operator-bridged read-only AWS demonstration.

The fixed 60 second request timeout accommodates the operator tool bridge; this
entrypoint does not alter production worker/client timeouts. No cloud keys load.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

from agents import Agent, RunConfig, Runner, function_tool, set_tracing_disabled
from agents.testing import ModelStep, ScriptedModel, assistant_message, function_call

from integration.client import ActionDenied, ControllerClient, ControllerUnavailable
from integration.process import signal_ready
from integration.telemetry import AgentTrace


async def run_plan(url, token, plan, on_ready=None):
    set_tracing_disabled(True)
    client = ControllerClient(url, token, timeout=60)
    trace = AgentTrace(model_mode="scripted")
    results = []

    @function_tool(failure_error_function=None)
    async def protected_action(proposal_json: str) -> str:
        """Request an operation from the trusted controller."""
        try:
            proposal = json.loads(proposal_json)
        except ValueError:
            raise ActionDenied("malformed_proposal") from None
        if type(proposal) is not dict:
            raise ActionDenied("malformed_proposal")
        operation = proposal.get("operation_id")
        trace.emit("action_proposed", operation_id=operation)
        try:
            result = await asyncio.to_thread(client.act, proposal)
        except ActionDenied as exc:
            trace.bind(client.trace_context)
            trace.emit("action_result", operation_id=operation,
                       status=exc.observed_status or "denied", reason=str(exc))
            raise
        except ControllerUnavailable:
            trace.bind(client.trace_context)
            trace.emit("action_result", operation_id=operation,
                       status="held", reason="controller_unavailable")
            raise
        trace.bind(client.trace_context)
        trace.emit("action_result", operation_id=operation, status="allowed", reason=result.get("reason"))
        safe = {key: result[key] for key in ("status", "reason", "receipt", "replayed") if key in result}
        results.append(safe)
        return json.dumps(safe, allow_nan=False)

    steps = [ModelStep(output=[function_call("protected_action", {
        "proposal_json": json.dumps(attempt, allow_nan=False)}, call_id=f"identity-{index}")])
        for index, attempt in enumerate(plan)]
    steps.append(ModelStep(output=[assistant_message("Identity demonstration finished.")]))
    agent = Agent(name="untrusted-scripted-identity-agent", instructions="Propose the provided actions.",
                  model=ScriptedModel(steps, emit_traces=False), tools=[protected_action])
    if on_ready:
        on_ready()
    try:
        await Runner.run(agent, "Execute the supplied demonstration plan.", max_turns=5,
                         run_config=RunConfig(tracing_disabled=True), hooks=trace)
        return trace.finish({"status": "completed", "results": results, "worker_pid": os.getpid()})
    except Exception as exc:
        cause = exc
        while cause.__cause__ is not None:
            cause = cause.__cause__
        if isinstance(cause, ActionDenied):
            status, reason = "denied", str(cause)
        elif isinstance(cause, ControllerUnavailable):
            status, reason = "blocked", "controller_unavailable"
        else:
            status, reason = "error", "sdk_run_failed"
        return trace.finish({"status": status, "reason": reason, "results": results,
                             "worker_pid": os.getpid()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path)
    args = parser.parse_args()
    token = os.environ.get("CONTROLLER_WORKER_TOKEN", "")
    if not token:
        result = {"status": "blocked", "reason": "worker_identity_required"}
    else:
        try:
            if args.plan.stat().st_size > 4096:
                raise ValueError("plan_limit")
            plan = json.loads(args.plan.read_text())
            if type(plan) is not list or len(plan) != 2 or any(type(item) is not dict for item in plan):
                raise ValueError("invalid_plan")
            result = asyncio.run(run_plan(args.url, token, plan,
                                          on_ready=lambda: signal_ready(args.ready_file)))
        except (OSError, TypeError, ValueError):
            result = {"status": "error", "reason": "invalid_worker_input"}
    print(json.dumps(result, allow_nan=False))
    return {"completed": 0, "denied": 3}.get(result["status"], 2)


if __name__ == "__main__":
    raise SystemExit(main())
