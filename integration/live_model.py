"""Agents SDK model client: authenticated controller HTTP, no provider credential."""
from __future__ import annotations

import asyncio
import hashlib
import json

from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage

from .client import ActionDenied, ControllerClient, ControllerUnavailable


class ControllerModel(Model):
    """Only model transport is /model; unsupported SDK features fail closed."""
    def __init__(self, client: ControllerClient):
        self.client = client
        self.measured_usage = []

    async def get_response(self, system_instructions, input, model_settings, tools,
                           output_schema, handoffs, tracing, *, previous_response_id=None,
                           conversation_id=None, prompt=None):
        if (handoffs or output_schema is not None or previous_response_id is not None
                or conversation_id is not None or prompt is not None
                or any(getattr(tool, "name", None) != "protected_action" for tool in tools)):
            raise ActionDenied("unsupported_model_feature")
        # Encode the SDK transcript as untrusted plain text. No arbitrary provider
        # input item, hosted tool, remote URL, model setting, or tool schema crosses
        # the controller's fixed provider request boundary.
        transcript = json.dumps({"instructions": system_instructions, "transcript": input},
                                sort_keys=True, separators=(",", ":"), allow_nan=False)
        operation_id = "model-" + hashlib.sha256(transcript.encode()).hexdigest()
        result = await asyncio.to_thread(self.client.request, "/model",
                                        {"operation_id": operation_id, "prompt": transcript})
        if result.get("status") != "allowed":
            reason = result.get("reason")
            # Durable replay/claim/recovery holds may represent a request that
            # already reached the provider. These two gateway budget holds
            # precede dispatch; treat other holds conservatively.
            if result.get("status") == "held" and reason not in (
                    "project_budget_denied", "project_budget_unavailable"):
                raise ActionDenied("model_outcome_unknown")
            if not isinstance(reason, str) or not reason.replace("_", "").isalnum():
                reason = "model_authorization_denied"
            raise ActionDenied(reason[:128])
        try:
            receipt = result["receipt"]
            usage = receipt["usage"]
            if usage.get("source") != "provider_measured":
                raise ValueError("unknown_usage")
            counts = {key: usage[key] for key in ("input_tokens", "output_tokens", "total_tokens")}
            if any(type(value) is not int or value < 0 for value in counts.values()):
                raise ValueError("unknown_usage")
            output = []
            for item in receipt["output"]:
                if item["type"] == "function_call" and item["name"] == "protected_action":
                    output.append(ResponseFunctionToolCall.model_validate(item))
                elif item["type"] == "message":
                    output.append(ResponseOutputMessage.model_validate(item))
                else:
                    raise ValueError("invalid_output")
            self.measured_usage.append(counts)
            return ModelResponse(output=output, usage=Usage(requests=1, **counts), response_id=None)
        except (KeyError, TypeError, ValueError):
            raise ControllerUnavailable("invalid_model_response") from None

    async def stream_response(self, *args, **kwargs):
        raise ActionDenied("streaming_not_supported")
        yield  # Makes this an async iterator without a hidden fallback.
