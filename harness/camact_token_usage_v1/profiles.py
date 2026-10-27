"""Small, wire-evidence based provider profiles. No networking or credentials.

A profile only selects/augments usage fields; it never edits model requests.
Add a profile here for a gateway with a different *documented* wire contract.
"""
from copy import deepcopy


def counter(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def zcloud_matches(raw, protocol):
    billing = raw.get("billing_usage")
    return (
        isinstance(billing, dict) and billing.get("source") == "oai_chat"
        and billing.get("semantic") == "openai"
    ) or any(k.startswith("kiro_") for k in raw) or (
        "claude_cache_creation_5_m_tokens" in raw
        and "claude_cache_creation_1_h_tokens" in raw
        and protocol in {"openai-chat", "openai-responses"}
    )


def zcloud(raw, protocol):
    selected, selected_protocol = deepcopy(raw), protocol
    provenance, diagnostics, extensions = {}, [], {}
    billing = raw.get("billing_usage")
    if (protocol in {"anthropic-messages", "deepseek-messages"}
            and isinstance(billing, dict) and billing.get("source") == "oai_chat"
            and billing.get("semantic") == "openai"):
        nested = billing.get("openai_usage")
        # A malformed authoritative layer must not silently fall back to a
        # different scope. The standard normalizer will mark missing counters.
        selected = deepcopy(nested) if isinstance(nested, dict) else {}
        selected_protocol = "openai-chat"
        provenance["input_tokens"] = provenance["output_tokens"] = provenance["total_tokens"] = (
            "billing_usage[source=oai_chat,semantic=openai].openai_usage")
        diagnostics.append("explicit_nested_openai_billing_scope")
    if selected_protocol in {"openai-chat", "openai-responses"}:
        a, b = selected.get("claude_cache_creation_5_m_tokens"), selected.get("claude_cache_creation_1_h_tokens")
        detail_key = "prompt_tokens_details" if selected_protocol == "openai-chat" else "input_tokens_details"
        detail = selected.get(detail_key)
        detail = detail if isinstance(detail, dict) else {}
        existing = selected.get("cache_creation_input_tokens", detail.get("cached_creation_tokens"))
        # Responses' 5m/1h extensions are zero even when its canonical detail
        # reports nonzero writes (8/22 archived requests). They cannot establish
        # a missing write count. Chat/billing semantics retain their own rule.
        if selected_protocol == "openai-chat" and counter(a) and counter(b) and existing is None:
            selected["cache_creation_input_tokens"] = a + b
            provenance["cache_write_tokens"] = ("selected_usage.claude_cache_creation_5_m_tokens"
                                                "+selected_usage.claude_cache_creation_1_h_tokens")
        if selected_protocol == "openai-responses":
            def details(key):
                value = raw.get(key)
                if value is not None and not isinstance(value, dict):
                    diagnostics.append("responses_invalid_detail_container:" + key)
                return value if isinstance(value, dict) else {}
            response_input = details("input_tokens_details")
            chat_input = details("prompt_tokens_details")
            read, chat_read = response_input.get("cached_tokens"), chat_input.get("cached_tokens")
            if counter(read) and counter(chat_read) and read != chat_read:
                diagnostics.append("responses_cache_read_chat_alias_disagrees")
            elif read is None and counter(chat_read):
                diagnostics.append("responses_cache_read_missing_chat_alias_ignored")
            if "cache_write_tokens" in response_input:
                write = response_input["cache_write_tokens"]
                write_source = "input_tokens_details.cache_write_tokens"
            else:
                write = raw.get("cache_creation_input_tokens")
                write_source = "cache_creation_input_tokens"
                if write is None:
                    write = response_input.get("cached_creation_tokens")
                    write_source = "input_tokens_details.cached_creation_tokens"
            if counter(a) and counter(b):
                if write is None:
                    diagnostics.append("responses_cache_write_extension_scope_unverified")
                elif counter(write) and write != a + b:
                    diagnostics.append("responses_cache_write_extension_disagrees")
            provenance.update(input_tokens="input_tokens", output_tokens="output_tokens",
                              total_tokens="input_tokens+output_tokens; checked against total_tokens",
                              cache_read_tokens="input_tokens_details.cached_tokens",
                              cache_write_tokens=write_source,
                              reasoning_tokens="output_tokens_details.reasoning_tokens")
            for label, value in (("read", read), ("write", write)):
                if counter(value) and counter(raw.get("input_tokens")) and value > raw["input_tokens"]:
                    diagnostics.append("responses_cache_" + label + "_exceeds_declared_input")
            # Never use Chat's cached_tokens alias: it disagrees with Responses
            # on this gateway. Reasoning is usable only with equal I/O aliases.
            detail = details("output_tokens_details")
            alias = details("completion_tokens_details")
            if (("output_tokens_details" not in raw
                    or isinstance(raw.get("output_tokens_details"), dict) and "reasoning_tokens" not in detail)
                    and counter(raw.get("input_tokens")) and counter(raw.get("output_tokens"))
                    and raw.get("input_tokens") == raw.get("prompt_tokens")
                    and raw.get("output_tokens") == raw.get("completion_tokens")
                    and counter(alias.get("reasoning_tokens"))):
                selected["output_tokens_details"] = {**detail, "reasoning_tokens": alias["reasoning_tokens"]}
                provenance["reasoning_tokens"] = "completion_tokens_details.reasoning_tokens; equal I/O aliases"
    for key in ("kiro_actual_input_tokens", "kiro_billable_input_tokens", "kiro_excluded_input_tokens"):
        if counter(raw.get(key)):
            extensions[key] = raw[key]
    if extensions:
        extensions["scope"] = "provider_extension_separate_from_standardized_api_usage"
        actual, billable, excluded = (extensions.get(k) for k in (
            "kiro_actual_input_tokens", "kiro_billable_input_tokens", "kiro_excluded_input_tokens"))
        if all(v is not None for v in (actual, billable, excluded)):
            extensions["actual_equals_billable_plus_excluded"] = actual == billable + excluded
            if actual != billable + excluded:
                diagnostics.append("kiro_extension_arithmetic_mismatch")
    return selected, selected_protocol, provenance, diagnostics, extensions


PROFILES = {"zcloud": (zcloud_matches, zcloud)}


def select(raw, protocol, profile=None):
    if profile == "standard":
        return raw, protocol, {}, [], {}, "standard"
    if profile is not None and profile not in PROFILES:
        raise ValueError("unknown usage profile")
    for name, (matches, transform) in PROFILES.items():
        if profile == name or (profile is None and matches(raw, protocol)):
            return (*transform(raw, protocol), name)
    return raw, protocol, {}, [], {}, "standard"
