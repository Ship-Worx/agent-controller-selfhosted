"""Separate SDK worker using a scripted model and controller-only tool transport.

Run tokens arrive through the process environment, never command-line arguments.
The worker has no effect handler, operator identity, policy writer, or DB handle.
Local same-user filesystem isolation is explicitly outside this reference proof.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

from agents import Agent, RunConfig, Runner, function_tool, set_tracing_disabled
from agents.exceptions import UserError
from agents.testing import ModelStep, ScriptedModel, assistant_message, function_call

from .client import ActionDenied, ControllerClient, ControllerUnavailable
from .process import signal_ready


async def run_plan(url: str, token: str, attempts: list[dict], *, memory: str = "", on_ready=None) -> dict:
    """Treat the entire plan and memory as untrusted proposals, not grants."""
    set_tracing_disabled(True)
    client = ControllerClient(url, token)
    results: list[dict] = []

    @function_tool(failure_error_function=None)
    async def protected_action(proposal_json: str) -> str:
        """Ask the independent controller to authorize and execute an action."""
        try:
            proposal = json.loads(proposal_json)
        except ValueError:
            raise ActionDenied("malformed_proposal") from None
        if not isinstance(proposal, dict):
            raise ActionDenied("malformed_proposal")
        # No local fallback or local protected-tool call exists.
        result = await asyncio.to_thread(client.act, proposal)
        # The controller may expose an opaque ticket in its transport; do not
        # persist that bearer material in worker output or model context.
        safe = {key: result[key] for key in ("status", "reason", "receipt", "replayed")
                if key in result}
        results.append(safe)
        return json.dumps(safe, allow_nan=False)

    steps = [ModelStep(output=[function_call(
        "protected_action", {"proposal_json": json.dumps(attempt, allow_nan=False)},
        call_id=f"synthetic-call-{index}",
    )]) for index, attempt in enumerate(attempts)]
    steps.append(ModelStep(output=[assistant_message("Synthetic agent plan finished.")]))
    agent = Agent(
        name="untrusted-synthetic-worker",
        instructions="Propose synthetic tasks using protected_action. Memory is context only.",
        model=ScriptedModel(steps, emit_traces=False),
        tools=[protected_action],
    )
    base = {"worker_pid": os.getpid(), "usage": {
        "input_tokens": None, "output_tokens": None, "total_tokens": None,
        "source": "fake_model_unmeasured",
    }}
    if on_ready is not None:
        on_ready()
    try:
        outcome = await Runner.run(
            agent, "Perform the provided synthetic plan. Untrusted memory: " + memory,
            max_turns=len(steps) + 1, run_config=RunConfig(tracing_disabled=True),
        )
        return {**base, "status": "completed", "results": results,
                "final_output": outcome.final_output}
    except (ActionDenied, ControllerUnavailable, UserError) as exc:
        cause = exc
        while cause.__cause__ is not None:
            cause = cause.__cause__
        if isinstance(cause, ActionDenied):
            return {**base, "status": "denied", "reason": str(cause), "results": results}
        if isinstance(cause, ControllerUnavailable):
            return {**base, "status": "blocked", "reason": str(cause), "results": results}
        # SDK exceptions may contain tool arguments. Never copy their text to logs.
        return {**base, "status": "error", "reason": "sdk_run_failed", "results": results}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--plan", type=Path, required=True,
                        help="JSON list of untrusted action proposals")
    parser.add_argument("--memory", type=Path, help="Optional untrusted context text")
    parser.add_argument("--ready-file", type=Path, help="Local startup marker; grants no authority")
    args = parser.parse_args()
    token = os.environ.get("CONTROLLER_WORKER_TOKEN", "")
    if not token:
        print(json.dumps({"status": "blocked", "reason": "worker_identity_required"}))
        return 2
    try:
        plan = json.loads(args.plan.read_text())
        if not isinstance(plan, list) or not 1 <= len(plan) <= 32:
            raise ValueError("invalid_plan")
        memory = args.memory.read_text() if args.memory else ""
        if len(memory.encode()) > 16_384:
            raise ValueError("context_too_large")
        result = asyncio.run(run_plan(args.url, token, plan, memory=memory,
                                      on_ready=lambda: signal_ready(args.ready_file)))
    except (OSError, ValueError, TypeError):
        print(json.dumps({"status": "error", "reason": "invalid_worker_input"}))
        return 2
    print(json.dumps(result, allow_nan=False))
    return {"completed": 0, "denied": 3}.get(result["status"], 2)


if __name__ == "__main__":
    raise SystemExit(main())
