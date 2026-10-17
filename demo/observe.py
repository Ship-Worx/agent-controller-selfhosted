"""Show correlated agent observations and controller decisions from a real demo.

The two processes keep independent clocks. Grouping their events by operation
hash within the same run is a causal join, not a claim of globally ordered timestamps. Agent
observations do not authorize execution or prove the absence of an effect.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile

from .contract import _safe_agent_trace, _safe_controller_events, demonstrate
from .local import PROJECT


def _event_label(event):
    label = event["event"]
    codes = [event[key] for key in ("status", "reason") if key in event]
    return label + (" [" + ", ".join(codes) + "]" if codes else "")


def render_report(report, artifact_path):
    """Render only explicitly validated fields; missing evidence stays missing."""
    lines = [
        "Agent and controller observability demonstration",
        "Controller events record authorization and protected effects.",
        "Agent events are diagnostic observations and grant no authority.",
        "Agent tool events describe request wrappers; protected execution appears in the controller journal.",
        "Streams join by run and operation hashes. Each keeps its own order; cross-process clocks are not ordered.",
    ]
    observability = report.get("observability", {}) if type(report) is dict else {}
    if type(observability) is not dict:
        observability = {}
    agent_trace = None
    try:
        agent_trace = _safe_agent_trace(observability.get("agent_trace"))
    except (RuntimeError, TypeError, KeyError):
        lines.append("Agent stream unavailable or invalid; no agent activity can be inferred.")
    controller_events = None
    controller_trace = observability.get("controller_trace")
    try:
        if type(controller_trace) is not dict or type(controller_trace.get("events")) is not list:
            raise RuntimeError("controller_trace_missing")
        controller_events = _safe_controller_events(controller_trace["events"])
    except (RuntimeError, TypeError, KeyError):
        lines.append("Controller stream unavailable or invalid; authorization and effects are unconfirmed.")
    agent_events = [] if agent_trace is None else agent_trace["events"]
    if agent_trace is not None:
        lines.append("Agent invocation: " + agent_trace["invocation_id"])
        lines.append("Observed policy: " + agent_trace["policy_pin"])
        if agent_trace["truncated"] or agent_trace["unavailable"]:
            lines.append("Agent stream is incomplete; missing events do not establish that no action occurred.")
    controller_events = [] if controller_events is None else controller_events
    if (agent_trace is not None and controller_events
            and any(event["run_id_hash"] != agent_trace["run_id_hash"] for event in controller_events)):
        lines.append("Agent/controller run bindings differ; their operations are not correlated.")
    operations = dict.fromkeys(
        (event["run_id_hash"], event["operation_id_hash"])
        for event in controller_events if "operation_id_hash" in event)
    if agent_trace is not None:
        operations.update(dict.fromkeys(
            (agent_trace["run_id_hash"], event["operation_id_hash"])
            for event in agent_events if "operation_id_hash" in event))
    for run_hash, operation_hash in operations:
        lines.extend(["", "Run " + run_hash, "Operation " + operation_hash])
        agent_operation = [event for event in agent_events
                           if agent_trace["run_id_hash"] == run_hash
                           and event.get("operation_id_hash") == operation_hash]
        controller_operation = [event for event in controller_events
                                if event["run_id_hash"] == run_hash
                                and event.get("operation_id_hash") == operation_hash]
        if agent_operation:
            lines.append("  Agent stream (reported):")
            for event in agent_operation:
                lines.append(f"    seq={event['seq']} +{event['elapsed_ms']}ms: " + _event_label(event))
        else:
            lines.append("  No agent events recorded for this operation.")
        if controller_operation:
            lines.append("  Controller journal:")
            for event in controller_operation:
                lines.append(f"    event_id={event['event_id']}: " + _event_label(event))
        else:
            lines.append("  No controller events recorded for this operation; execution is unconfirmed.")
    invocation_events = [event for event in agent_events if "operation_id_hash" not in event]
    if invocation_events:
        lines.extend(["", "Other SDK observations (agent source order):"])
        for event in invocation_events:
            lines.append(f"  seq={event['seq']} +{event['elapsed_ms']}ms: " + _event_label(event))
    lines.extend(["", "Trace artifact: " + str(artifact_path)])
    if (type(report) is dict and report.get("mode") == "synthetic_local_processes"
            and report.get("live_model_calls") == 0 and report.get("aws_mutations") == 0):
        lines.append("Synthetic local processes; no live model calls or AWS mutations.")
    lines.append("This demonstration does not establish AWS or OS isolation.")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=PROJECT / ".runtime" / "observability-demo")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=args.output_dir.resolve()))
    output, _checks = demonstrate(run_dir)
    print(render_report(json.loads(output.read_text()), output))


if __name__ == "__main__":
    main()
