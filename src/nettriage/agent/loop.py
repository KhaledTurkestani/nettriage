"""The investigation loop.

The loop is written by hand rather than with the SDK's tool runner because it
has two phases the runner's per-turn hooks do not cover: a tool-call budget
that ends in a report instead of a cut-off, and a correction round driven by
the evidence check. Every step is also recorded as an event, which is what the
web UI's timeline and the replay mode are built from.

Rules the loop keeps, because the API depends on them:

* The conversation is append-only. The system prompt, the tool list and every
  earlier message stay byte-identical, and assistant turns are sent back
  unmodified, thinking blocks included. That keeps the prompt cache warm and
  the model's earlier reasoning valid.
* ``stop_reason`` is checked before anything else is read. A refusal ends the
  run; tools from a refused or cut-off turn are never executed.
* Requests opt in to server-side fallbacks. Security data can trip a safety
  classifier even in defensive work, and a fallback model then answers instead.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache

from pydantic import ValidationError

from .. import store
from ..classifier import ClassifierError
from ..classifier.model import FlowModel, load_model
from . import AgentError
from .prompts import CURRENT as DEFAULT_PROMPT, system_prompt
from .report import FindingCheck, Report, check_report, drop_failed
from .tools import TOOLS, run_tool

# The cheapest current model is the default; --model picks another. Which model is good
# enough for this job is a question for the evals, not for a default.
DEFAULT_MODEL = "claude-haiku-5-5"
DEFAULT_MAX_TOOL_CALLS = 30
MAX_TOKENS = 20_000  # thinking counts toward this, not only the reply
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Models documented to accept the server-side fallback opt-in. For any other model the
# parameter is left out: Claude Haiku 5.5 has no server-side fallback, and a model that does
# not know the parameter rejects the whole request.
FALLBACK_MODELS = frozenset({"claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"})
EFFORTS = ("low", "medium", "high", "xhigh", "max")
# Effort used when the caller names none. The API default is medium; for Claude Haiku 5.5 its
# documentation recommends high for longer agent tasks and strict instruction following.
EFFORT_BY_MODEL = {"claude-haiku-5-5": "high"}

# List prices in US dollars per million tokens, as rate cards: (largest prompt the card covers,
# prices). Claude Haiku 5.5 costs five times more per token once a prompt passes 100,000 tokens.
# Models that are not listed get token counts without a cost.
PRICES: dict[str, list[tuple[int | None, dict[str, float]]]] = {
    "claude-opus-5-5": [(None, {"input": 4.00, "output": 20.00, "cache_write": 5.00, "cache_read": 0.20})],
    "claude-sonnet-5-5": [(None, {"input": 2.00, "output": 10.00, "cache_write": 2.50, "cache_read": 0.10})],
    "claude-haiku-5-5": [
        (100_000, {"input": 0.10, "output": 0.50, "cache_write": 0.125, "cache_read": 0.01}),
        (None, {"input": 0.50, "output": 2.50, "cache_write": 0.625, "cache_read": 0.05}),
    ],
}


def default_effort(model: str) -> str:
    return EFFORT_BY_MODEL.get(model, "medium")


def turn_cost(model: str, usage: dict) -> float | None:
    """What one model turn cost at list prices, or None when the model's prices are not known."""
    cards = PRICES.get(model)
    if cards is None:
        return None
    prompt = usage["input_tokens"] + usage["cache_creation_input_tokens"] + usage["cache_read_input_tokens"]
    price = next(prices for limit, prices in cards if limit is None or prompt <= limit)
    return (
        usage["input_tokens"] * price["input"] + usage["output_tokens"] * price["output"]
        + usage["cache_creation_input_tokens"] * price["cache_write"]
        + usage["cache_read_input_tokens"] * price["cache_read"]
    ) / 1_000_000


BUDGET_SPENT = "The tool-call budget is used up, so this call was not run. Write the final report now from what you have already seen."


@dataclass
class Investigation:
    run_id: str
    capture_id: str
    model: str
    effort: str
    status: str = "running"  # completed | refused | failed
    report: Report | None = None
    error: str | None = None
    validation: dict = field(default_factory=dict)
    usage: dict = field(default_factory=lambda: {
        "input_tokens": 0, "output_tokens": 0, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
    })
    # Estimated at list prices, turn by turn. None once any turn was served by a model whose
    # prices are not known.
    cost_usd: float | None = 0.0
    api_calls: int = 0
    tool_calls: int = 0
    fallback_used: bool = False
    served_by: list[str] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    # Name of the system prompt version (see prompts.py). Records written before prompts had
    # versions lack it; they used "baseline".
    prompt: str = DEFAULT_PROMPT
    max_tool_calls: int = 0  # the budget the run was given; 0 in records written before it was kept


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_run_id(capture_id: str) -> str:
    """An id for a run that is about to start. The web API makes it up front, so a page can follow the run."""
    return f"{capture_id}-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4]}"


def _blocks_to_echo(content: list) -> list:
    """The assistant content to send back, following the API's rule for turns a fallback model finished.

    Normally that is the content unchanged. If the turn switched models part-way, thinking and
    tool_use blocks from before the last ``fallback`` block must be left out, and the fallback
    block must stay where it was.
    """
    boundary = max((i for i, block in enumerate(content) if block.type == "fallback"), default=-1)
    if boundary < 0:
        return list(content)
    dropped = ("thinking", "redacted_thinking", "tool_use")
    return [block for i, block in enumerate(content) if i >= boundary or block.type not in dropped]


def _correction_message(failed: list[FindingCheck]) -> str:
    lines = ["The evidence check rejected the following finding(s):", ""]
    for check in failed:
        lines.append(f"- Finding {check.index + 1}, \"{check.title}\":")
        lines.extend(f"    {problem}" for problem in check.problems)
    lines += [
        "",
        "Fix each one by citing flows that exist and involve the addresses you name; run queries to select "
        "them if you still have tool calls. Remove a finding you cannot support. Then answer with the "
        "complete corrected report. This is the only correction round: findings that fail again are removed.",
    ]
    return "\n".join(lines)


def first_message(meta: store.CaptureMeta, max_tool_calls: int) -> str:
    """The request that opens an investigation. It carries facts about the capture, never its name."""
    return (
        f"Investigate the capture that has been loaded for you. It holds {meta.flow_count:,} flows between "
        f"{meta.first_ts} and {meta.last_ts}. You may make up to {max_tool_calls} tool calls. "
        "When you are done, answer with the report."
    )


def make_client(**options):
    """An Anthropic client using credentials from the environment.

    ``options`` are passed to the client, e.g. ``max_retries`` and ``timeout``.
    """
    import anthropic

    try:
        client = anthropic.Anthropic(**options)
    except anthropic.AnthropicError as exc:
        raise AgentError(f"Could not create the API client: {exc}") from exc
    if not (client.api_key or client.auth_token or client.credentials):
        raise AgentError(
            "No API key found. Put ANTHROPIC_API_KEY=... in a .env file in this folder, or set it in your "
            "environment, then run the command again."
        )
    return client


def investigate(
    capture_id: str,
    *,
    client=None,
    model: str = DEFAULT_MODEL,
    effort: str | None = None,
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS,
    prompt: str = DEFAULT_PROMPT,
    on_event: Callable[[dict], None] | None = None,
    run_id: str | None = None,
) -> Investigation:
    """Investigate one capture and return the checked report with a record of every step.

    Each call to this function sends requests to the Claude API and is billed to
    the caller's key.
    """
    import anthropic

    effort = effort or default_effort(model)
    if effort not in EFFORTS:
        raise AgentError(f"effort must be one of: {', '.join(EFFORTS)}.")
    if max_tool_calls < 1:
        raise AgentError("max_tool_calls must be at least 1.")
    system = system_prompt(prompt)
    try:
        meta = store.load_meta(capture_id)
    except store.CaptureError as exc:
        raise AgentError(str(exc)) from exc
    try:
        classifier: FlowModel | None = load_model()
    except ClassifierError:
        classifier = None  # classify_flows will explain this to the model when called

    client = client or make_client()
    run = Investigation(
        run_id=run_id or new_run_id(capture_id),
        capture_id=capture_id, model=model, effort=effort, started_at=_now(), prompt=prompt,
        max_tool_calls=max_tool_calls,
    )

    def emit(event: dict) -> None:
        event = {"n": len(run.events) + 1, **event}
        run.events.append(event)
        if on_event:
            on_event(event)

    def finish(status: str, error: str | None = None) -> Investigation:
        run.status, run.error, run.finished_at = status, error, _now()
        emit({"type": "end", "status": status, "error": error})
        return run

    messages: list[dict] = [{"role": "user", "content": first_message(meta, max_tool_calls)}]
    corrected = False
    first_checks: list[FindingCheck] | None = None
    reported = 0
    max_api_calls = max_tool_calls + 8

    while True:
        if run.api_calls >= max_api_calls:
            return finish("failed", f"Stopped after {run.api_calls} model calls without a report.")
        try:
            message = _request(client, messages, model=model, effort=effort, system=system)
        except anthropic.AuthenticationError as exc:
            raise AgentError("The API key was rejected. Set ANTHROPIC_API_KEY to a valid key.") from exc
        except anthropic.APIError as exc:
            return finish("failed", f"API error: {getattr(exc, 'message', None) or exc}")
        run.api_calls += 1
        usage = message.usage
        turn_usage = {key: getattr(usage, key, None) or 0 for key in run.usage}
        for key, value in turn_usage.items():
            run.usage[key] += value
        cost = turn_cost(message.model, turn_usage)
        run.cost_usd = None if cost is None or run.cost_usd is None else round(run.cost_usd + cost, 8)
        if message.model not in run.served_by:
            run.served_by.append(message.model)
        if any(block.type == "fallback" for block in message.content) or message.model != model:
            run.fallback_used = True

        emit({
            "type": "model",
            "stop_reason": message.stop_reason,
            "served_by": message.model,
            "thinking": [b.thinking for b in message.content if b.type == "thinking" and b.thinking],
            "text": "".join(b.text for b in message.content if b.type == "text"),
            "tool_calls": [{"name": b.name, "input": b.input} for b in message.content if b.type == "tool_use"],
            "usage": turn_usage,
        })

        if message.stop_reason == "refusal":
            details = getattr(message, "stop_details", None)
            category = getattr(details, "category", None)
            return finish("refused", f"The model declined this request (category: {category or 'not given'}).")
        if message.stop_reason == "max_tokens":
            return finish("failed", "A model turn hit the output limit before it finished.")

        blocks = _blocks_to_echo(message.content)
        messages.append({"role": "assistant", "content": blocks})
        tool_uses = [block for block in blocks if block.type == "tool_use"]

        if tool_uses:
            results: list[dict] = []
            for block in tool_uses:
                if run.tool_calls >= max_tool_calls:
                    content, is_error, took = BUDGET_SPENT, True, 0.0
                else:
                    result, took = run_tool(capture_id, block.name, block.input, model=classifier)
                    content, is_error = result.content, result.is_error
                    run.tool_calls += 1
                entry = {"type": "tool_result", "tool_use_id": block.id, "content": content}
                if is_error:
                    entry["is_error"] = True
                results.append(entry)
                emit({"type": "tool", "name": block.name, "input": block.input, "output": content,
                      "is_error": is_error, "ms": round(took, 1)})
            left = max_tool_calls - run.tool_calls
            if left in (1, 3):
                results.append({"type": "text", "text": f"Tool calls left: {left}."})
            messages.append({"role": "user", "content": results})
            continue

        if message.stop_reason in ("tool_use", "pause_turn"):
            # A turn that asked for tools but has none left to answer (they were issued before a
            # model switch). Ask again rather than guess.
            messages.append({"role": "user", "content": "Your tool calls did not go through. Issue them again, "
                                                        "or answer with the report."})
            continue

        text = "".join(block.text for block in blocks if block.type == "text")
        try:
            report = Report.model_validate_json(text)
        except ValidationError:
            return finish("failed", "The model's final answer was not a valid report.")

        checks = check_report(report, capture_id)
        failed = [check for check in checks if not check.ok]
        if first_checks is None:
            first_checks, reported = checks, len(report.findings)
        emit({
            "type": "evidence_check",
            "round": 2 if corrected else 1,
            "findings": len(report.findings),
            "rejected": [{"finding": c.title, "problems": c.problems} for c in failed],
        })
        if failed and not corrected:
            corrected = True
            messages.append({"role": "user", "content": _correction_message(failed)})
            continue

        run.report = drop_failed(report, checks)
        run.validation = {
            "findings_reported": reported,
            "rejected_on_first_check": sum(1 for c in first_checks if not c.ok),
            "correction_round": corrected,
            "findings_removed": len(failed),
            "findings_kept": len(run.report.findings),
        }
        emit({"type": "report", "verdict": run.report.verdict, "findings": len(run.report.findings)})
        return finish("completed")


@lru_cache(maxsize=1)
def _report_schema() -> dict:
    import anthropic

    return anthropic.transform_schema(Report)


def _request(client, messages: list[dict], *, model: str, effort: str, system: str):
    """One model turn, streamed so long turns cannot hit an HTTP timeout.

    The report schema is passed as ``output_config.format`` rather than through the SDK's
    ``output_format`` helper. The helper parses the final text inside the SDK and raises when
    it is not valid JSON, which is exactly what a refused or cut-off turn looks like; the loop
    has to see ``stop_reason`` first.
    """
    fallback = {"betas": [FALLBACK_BETA], "fallbacks": "default"} if model in FALLBACK_MODELS else {}
    for attempt in (1, 2):
        try:
            with client.beta.messages.stream(
                model=model,
                max_tokens=MAX_TOKENS,
                system=system,
                tools=TOOLS,
                messages=messages,
                thinking={"type": "adaptive", "display": "summarized"},
                output_config={"effort": effort, "format": {"type": "json_schema", "schema": _report_schema()}},
                cache_control={"type": "ephemeral"},
                **fallback,
            ) as stream:
                return stream.get_final_message()
        except ValueError:
            # The SDK could not parse a streamed tool input. There is no tool call to answer,
            # so the request is issued again, once.
            if attempt == 2:
                raise AgentError("The model's tool input could not be parsed, twice in a row.") from None
