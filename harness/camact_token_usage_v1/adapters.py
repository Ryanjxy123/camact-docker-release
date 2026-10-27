"""Provider wire adapters: snapshots within ONE physical HTTP request only.

No CLI session totals enter the ledger. Stream snapshots replace fields rather
than add them. Unknown counters stay None; provider extensions remain available
as numeric raw usage, without storing prompts, credentials or generated text.
"""
from __future__ import annotations
import gzip
import json
import re
from urllib.parse import urlsplit
from .profiles import select

NORMALIZER_VERSION = "camact.usage_normalizer.v2.1"
METRIC_SCOPE = "api_returned_standardized_agent_model_usage"

FIELDS = ("input_tokens", "output_tokens", "total_tokens", "uncached_input_tokens",
          "cache_read_tokens", "cache_write_tokens", "reasoning_tokens")


def protocol_for(url):
    route = urlsplit(url).path
    if route.endswith(("/responses", "/responses/compact")):
        return "openai-responses"
    if route.endswith("/chat/completions"):
        return "openai-chat"
    if route.endswith("/messages"):
        return "anthropic-messages"
    if route.endswith((":generateContent", ":streamGenerateContent")):
        return "google-generative-language"
    return None  # countTokens, files, auth and metadata are not model calls.


def numeric_usage(value):
    """Keep all numeric provider details; never persist arbitrary usage strings."""
    if isinstance(value, dict):
        result = {k: numeric_usage(v) for k, v in value.items()
                  if v is None or (isinstance(v, (dict, list, int, float)) and not isinstance(v, bool))}
        if value.get("modality") in {"TEXT", "IMAGE", "VIDEO", "AUDIO", "DOCUMENT"}:
            result["modality"] = value["modality"]
        for key in ("usage_semantic", "usage_source", "semantic", "source"):
            if value.get(key) in ("openai", "anthropic", "kiro", "zcloud", "oai_chat"):
                result[key] = value[key]
        return result
    if isinstance(value, list):
        return [numeric_usage(v) for v in value if isinstance(v, (dict, list, int, float)) and not isinstance(v, bool)]
    return value


def _standard_normalize(raw, protocol):
    result = dict.fromkeys(FIELDS)
    problems = []
    def number(key, source=None):
        value = (raw if source is None else source).get(key)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            problems.append("invalid_counter:" + key)
            return None
        return value
    def details(key):
        return raw.get(key) if isinstance(raw.get(key), dict) else {}
    if protocol in {"anthropic-messages", "deepseek-messages"}:
        uncached = number("input_tokens")
        read, write = number("cache_read_input_tokens"), number("cache_creation_input_tokens")
        # Absent optional counters differ from an explicitly unknown/invalid
        # component. The latter cannot support an exact inclusive input.
        cache_unknown = any(key in raw and value is None for key, value in (
            ("cache_read_input_tokens", read), ("cache_creation_input_tokens", write)))
        inp = None if uncached is None or cache_unknown else uncached + (read or 0) + (write or 0)
        out = number("output_tokens")
        reasoning = number("thinking_tokens", details("output_tokens_details"))
    elif protocol == "google-generative-language":
        inp = number("promptTokenCount")
        out = number("candidatesTokenCount")
        reasoning = number("thoughtsTokenCount")
        if out is not None:
            out = out + reasoning if reasoning is not None else None
        # A separately reported tool-use prompt is also model input.
        tool_prompt = number("toolUsePromptTokenCount")
        if inp is not None:
            inp = (None if "toolUsePromptTokenCount" in raw and tool_prompt is None
                   else inp + (tool_prompt or 0))
        read, write = number("cachedContentTokenCount"), None
        uncached = inp - read if inp is not None and read is not None else None
        total = number("totalTokenCount")
        if out is None and inp is not None and total is not None and total >= inp:
            out = total - inp  # exact reported total, never a text estimate
        candidates = number("candidatesTokenCount")
        if candidates is not None and out is not None and candidates > out:
            problems.append("candidates_exceed_output")
    elif protocol in {"openai-chat", "openai-responses"}:
        chat = protocol == "openai-chat"
        inp = number("prompt_tokens" if chat else "input_tokens")
        out = number("completion_tokens" if chat else "output_tokens")
        read = number("cached_tokens", details("prompt_tokens_details" if chat else "input_tokens_details"))
        if read is None and "prompt_cache_hit_tokens" in raw:
            read = number("prompt_cache_hit_tokens")
        input_detail = details("prompt_tokens_details" if chat else "input_tokens_details")
        if not chat and "cache_write_tokens" in input_detail:
            # Native Responses/Codex field; provider aliases are only fallback
            # when this field is absent, never when explicitly zero or unknown.
            write = number("cache_write_tokens", input_detail)
            if write is not None:
                for alias in (raw.get("cache_creation_input_tokens"), input_detail.get("cached_creation_tokens")):
                    if isinstance(alias, int) and not isinstance(alias, bool) and alias >= 0 and alias != write:
                        problems.append("cache_write_alias_mismatch")
                        break
        else:
            write = number("cache_creation_input_tokens")
            if write is None:
                write = number("cached_creation_tokens", input_detail)
        reasoning = number("reasoning_tokens", details("completion_tokens_details" if chat else "output_tokens_details"))
        uncached = inp - read - write if all(v is not None for v in (inp, read, write)) else None
    else:
        return result, ["unsupported_protocol"]
    result.update(input_tokens=inp, output_tokens=out, uncached_input_tokens=uncached,
                  cache_read_tokens=read, cache_write_tokens=write, reasoning_tokens=reasoning)
    if inp is not None and out is not None:
        result["total_tokens"] = inp + out
    reported = number("totalTokenCount" if protocol == "google-generative-language" else "total_tokens")
    if reported is not None and result["total_tokens"] is not None and reported != result["total_tokens"]:
        problems.append("provider_total_mismatch")
    if (uncached is not None and uncached < 0) or (
            inp is not None and (read or 0) + (write or 0) > inp):
        problems.append("cache_exceeds_input")
        result["uncached_input_tokens"] = None
    if reasoning is not None and out is not None and reasoning > out:
        problems.append("reasoning_exceeds_output")
    if result["total_tokens"] is None:
        problems.append("missing_input_or_output")
    return result, problems


def normalize_details(raw, protocol, *, profile=None):
    declared, _ = _standard_normalize(raw, protocol)
    reported_total = raw.get("totalTokenCount" if protocol == "google-generative-language" else "total_tokens")
    if isinstance(reported_total, int) and not isinstance(reported_total, bool) and reported_total >= 0:
        declared["total_tokens"] = reported_total
    selected, selected_protocol, provenance, diagnostics, extensions, profile_name = select(raw, protocol, profile)
    normalized, issues = _standard_normalize(selected, selected_protocol)
    states = {key: "known" if value is not None else "missing" for key, value in normalized.items()}
    for issue in issues:
        affected = ()
        if issue == "cache_exceeds_input":
            affected = ("input_tokens", "total_tokens", "uncached_input_tokens", "cache_read_tokens", "cache_write_tokens")
        elif issue == "provider_total_mismatch":
            affected = ("total_tokens",)
        elif issue == "cache_write_alias_mismatch":
            affected = ("cache_write_tokens", "uncached_input_tokens")
        elif issue in {"reasoning_exceeds_output", "candidates_exceed_output"}:
            affected = ("reasoning_tokens", "output_tokens", "total_tokens")
        elif issue.startswith("invalid_counter:"):
            # Invalid optional counters cannot support derived exact totals.
            key = issue.split(":", 1)[1]
            if key in {"cache_read_input_tokens", "cache_creation_input_tokens", "toolUsePromptTokenCount"}:
                affected = ("input_tokens", "total_tokens", "uncached_input_tokens")
        for key in affected:
            states[key] = "inconsistent" if normalized[key] is not None else "missing"
    comparable = {key: value if states[key] == "known" else None for key, value in normalized.items()}
    provenance = {key: provenance.get(key, selected_protocol + ":standard_usage_contract")
                  if normalized[key] is not None else "not_reported_or_not_derivable" for key in FIELDS}
    return {"usage": normalized, "normalized_tokens": normalized.copy(),
            "provider_reported_tokens": declared, "comparable_tokens": comparable,
            "field_status": states, "field_provenance": provenance,
            "normalizer_version": NORMALIZER_VERSION, "metric_scope": METRIC_SCOPE,
            "usage_profile": profile_name, "normalized_protocol": selected_protocol,
            "arithmetic_status": "inconsistent" if "provider_total_mismatch" in issues else
                                 "consistent" if normalized["total_tokens"] is not None else "unverified",
            "provider_extensions": extensions, "diagnostics": diagnostics, "issues": issues}


def normalize(raw, protocol, *, profile=None):
    result = normalize_details(raw, protocol, profile=profile)
    return result["usage"], result["issues"]


def _merge(target, values):
    for key, value in values.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _merge(target[key], value)
        else:
            target[key] = value


def extract(payload, protocol, *, encoding=None, profile=None):
    if encoding == "gzip" or payload[:2] == b"\x1f\x8b":
        payload = gzip.decompress(payload)
    text = payload.decode("utf-8", errors="replace")
    streamed = False
    malformed = False
    try:
        document = json.loads(text)
        documents = document if isinstance(document, list) else [document]
    except ValueError:
        streamed = True
        documents = []
        # SSE data can span lines; tolerate older captures without blank lines.
        for block in re.split(r"\r?\n\r?\n", text):
            lines = [line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")]
            if not lines:
                continue
            data = "\n".join(lines)
            if data.strip() == "[DONE]":
                continue
            try:
                documents.append(json.loads(data))
            except ValueError:
                for line in lines:
                    try:
                        documents.append(json.loads(line))
                    except ValueError:
                        malformed = True
    usage, calls = {}, {}
    response_id = model = None
    terminal = not streamed and bool(documents)
    snapshots = 0
    stream_error = False
    usage_errors = []
    # Native Responses can end authoritatively because its output budget was
    # reached. That is an incomplete generation, but its final Usage is still
    # the provider's exact accounting for this physical HTTP attempt. Preserve
    # the historical response_complete meaning and expose separate evidence.
    official_incomplete_usage = False
    provider_terminal_status = None
    hard_stream_error = False
    def call(item, fallback=None):
        if not isinstance(item, dict):
            return
        fn = item.get("function", item)
        ident = item.get("call_id") or item.get("id") or fallback
        name = fn.get("name")
        if name:
            ident = str(ident or "unidentified:" + str(len(calls)))
            calls[ident] = {"tool_call_id": ident, "name": name,
                            "identity_source": "provider" if item.get("id") or item.get("call_id") else "response_position"}
    for doc in documents:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("type", "")
        if kind in {"error", "response.failed", "response.incomplete"} or doc.get("error"):
            stream_error = True
        if kind in {"error", "response.failed"} or doc.get("error"):
            hard_stream_error = True
        if kind in {"message_stop", "response.completed"}:
            terminal = True
        if protocol == "openai-responses" and kind in {"response.completed", "response.incomplete", "response.failed"}:
            provider_terminal_status = kind.removeprefix("response.")
            response = doc.get("response")
            official_incomplete_usage = bool(
                kind == "response.incomplete" and isinstance(response, dict)
                and response.get("status") == "incomplete" and not response.get("error")
                and isinstance(response.get("usage"), dict)
                and isinstance(response.get("incomplete_details"), dict)
                and response["incomplete_details"].get("reason") == "max_output_tokens"
            )
        if protocol == "openai-responses" and kind in {"response.completed", "response.incomplete", "response.failed"}:
            # The terminal event is authoritative even when its response
            # object is missing or malformed; provisional usage cannot fill it.
            usage.clear()
            if not isinstance(doc.get("response"), dict):
                stream_error = True
                usage_errors.append("invalid_terminal_response")
        for container in (doc, doc.get("message"), doc.get("response")):
            if not isinstance(container, dict):
                continue
            if protocol == "openai-responses":
                status = container.get("status")
                if status in ("failed", "incomplete", "cancelled"):
                    stream_error = True
                elif (not streamed or kind == "response.completed") and status is not None and status != "completed":
                    terminal = False
            usage_key = "usage" if "usage" in container else "usageMetadata"
            found = container.get(usage_key)
            if isinstance(found, dict):
                _merge(usage, found)
                snapshots += bool(found)
            elif usage_key in container:
                usage.clear()
                if found is not None:
                    usage_errors.append("invalid_usage_container")
            response_id = container.get("id") or container.get("responseId") or response_id
            model = container.get("model") or container.get("modelVersion") or model
            for block in container.get("content", []) if isinstance(container.get("content"), list) else []:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    call(block)
            for item in container.get("output", []) if isinstance(container.get("output"), list) else []:
                if isinstance(item, dict) and item.get("type") in {"function_call", "custom_tool_call"}:
                    call(item)
        block = doc.get("content_block", {})
        if isinstance(block, dict) and block.get("type") == "tool_use":
            call(block)
        item = doc.get("item", {})
        if isinstance(item, dict) and item.get("type") in {"function_call", "custom_tool_call"}:
            call(item)
        for choice in doc.get("choices", []):
            if choice.get("finish_reason") is not None:
                terminal = True
            message = choice.get("message", choice.get("delta", {})) or {}
            for tool in message.get("tool_calls", []):
                call(tool, "index:" + str(tool.get("index", 0)))
        for i, candidate in enumerate(doc.get("candidates", [])):
            if candidate.get("finishReason"):
                terminal = True
            for j, part in enumerate(candidate.get("content", {}).get("parts", [])):
                if "functionCall" in part:
                    call(part["functionCall"], f"candidate:{i}:part:{j}")
    normalized = normalize_details(usage, protocol, profile=profile)
    normalized["issues"] += usage_errors + (["malformed_stream"] if malformed else [])
    return {"raw_usage": numeric_usage(usage), **normalized,
            "provider_response_id": response_id, "served_model_id": model,
            "associated_tool_calls": list(calls.values()), "usage_snapshot_count": snapshots,
            "response_complete": terminal and not stream_error,
            "officially_ended_incomplete_with_usage": bool(
                official_incomplete_usage and not hard_stream_error and not malformed and not usage_errors
                and all(normalized["comparable_tokens"].get(key) is not None
                        for key in ("input_tokens", "output_tokens", "total_tokens"))),
            "provider_terminal_status": provider_terminal_status,
            "streamed": streamed}


def tool_results(body):
    """Only explicit tool IDs in the actual next input, never text heuristics."""
    results = set()
    messages = body.get("messages", body.get("input", []))
    if not isinstance(messages, list):
        return []
    for message in messages:
        if not isinstance(message, dict):
            continue
        if message.get("role") == "tool" and message.get("tool_call_id"):
            results.add(str(message["tool_call_id"]))
        if message.get("type") in {"function_call_output", "custom_tool_call_output"} and message.get("call_id"):
            results.add(str(message["call_id"]))
        for block in message.get("content", []) if isinstance(message.get("content"), list) else []:
            if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("tool_use_id"):
                results.add(str(block["tool_use_id"]))
    return sorted(results)
