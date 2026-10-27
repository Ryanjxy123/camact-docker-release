"""Deterministic runtime guard for runaway user-clarification loops."""
from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any


MAX_ASK_USER = 15
MAX_NO_PROGRESS_REPEATS = 3
REPLY_SIMILARITY_THRESHOLD = 0.90
REQUIRED_FIELDS_RELEASED_HINT = (
    "The required user information has already been provided. "
    "Do not ask another clarification question; continue executing the task "
    "with the available tools or finish if the task is complete."
)


class ClarificationGuardTermination(RuntimeError):
    """The Agent trajectory must end as a scored Agent failure."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class AskDecision:
    action: str
    response: dict[str, Any] | None = None
    termination_reason: str | None = None


def _normalize_reply(value: Any) -> str:
    return re.sub(r"[\W_]+", " ", str(value).casefold(), flags=re.UNICODE).strip()


def _reply_similarity(left: Any, right: Any) -> float:
    a = _normalize_reply(left)
    b = _normalize_reply(right)
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def simulator_required_fields(simulator: dict[str, Any] | None) -> frozenset[str]:
    """Read required field names without exposing or changing hidden values."""
    if not isinstance(simulator, dict):
        return frozenset()
    policy = simulator.get("policy")
    if policy == "hybrid_user_simulator":
        fields = simulator.get("reveal_policy", {}).get("fields", [])
    elif policy == "field_gated_v1":
        fields = simulator.get("fields", [])
    else:
        return frozenset()
    return frozenset(
        str(field.get("field_name", "")).strip()
        for field in fields
        if isinstance(field, dict) and str(field.get("field_name", "")).strip()
    )


class ClarificationLoopGuard:
    """Track clarification attempts independently of retrieval/method logic."""

    def __init__(
        self,
        *,
        required_fields: set[str] | frozenset[str] | None = None,
        released_fields: set[str] | frozenset[str] | None = None,
        max_ask_user: int | None = MAX_ASK_USER,
        repeat_limit: int = MAX_NO_PROGRESS_REPEATS,
        similarity_threshold: float = REPLY_SIMILARITY_THRESHOLD,
    ) -> None:
        self.required_fields = frozenset(required_fields or ())
        self.released_fields = set(released_fields or ())
        self.max_ask_user = int(max_ask_user) if max_ask_user is not None else None
        self.repeat_limit = int(repeat_limit)
        self.similarity_threshold = float(similarity_threshold)
        self.ask_count = 0
        self.no_progress_repeat_count = 0
        self._last_no_progress_reply: str | None = None
        self._progress_epoch = 0
        self._last_reply_progress_epoch = -1
        self._release_warning_step: int | None = None
        self._successful_tool_steps: set[int] = set()

    @classmethod
    def from_environment(cls, environment: Any) -> "ClarificationLoopGuard":
        if getattr(environment, "instruction_simulator", False):
            # RuntimeEnvironment owns the actual interaction budget. Keep only
            # the repeated-reply safeguard here, with no second hidden turn cap.
            return cls(max_ask_user=None)
        state = getattr(environment, "state", {}).get("user_simulator", {})
        return cls(
            required_fields=simulator_required_fields(
                getattr(environment, "simulator", None)
            ),
            released_fields=set(state.get("released_fields", [])),
        )

    @property
    def required_fields_released(self) -> bool:
        return bool(self.required_fields) and self.required_fields.issubset(
            self.released_fields
        )

    def before_ask(self, step: int) -> AskDecision:
        self.ask_count += 1
        if self.max_ask_user is not None and self.ask_count > self.max_ask_user:
            return AskDecision(
                action="terminate",
                termination_reason="clarification_limit_exceeded",
            )
        if not self.required_fields_released:
            return AskDecision(action="call_simulator")
        if (
            self._release_warning_step is not None
            and step > self._release_warning_step
        ):
            return AskDecision(
                action="terminate",
                termination_reason="redundant_clarification_after_release",
            )
        if self._release_warning_step is None:
            self._release_warning_step = step
        return AskDecision(
            action="intercept",
            response={
                "ok": True,
                "tool": "ask_user",
                "intercepted": True,
                "simulator_called": False,
                "released_fields": [],
                "runtime_hint": REQUIRED_FIELDS_RELEASED_HINT,
            },
        )

    def after_simulator_response(
        self, step: int, response: dict[str, Any]
    ) -> str | None:
        del step  # Reserved for future trace diagnostics; policy is step-independent.
        released_now = {
            str(field)
            for field in response.get("released_fields", [])
            if str(field).strip()
        }
        new_fields = released_now - self.released_fields
        self.released_fields.update(released_now)
        if new_fields:
            self._record_progress()
            return None

        reply = str(response.get("content", ""))
        similar = (
            self._last_no_progress_reply is not None
            and self._last_reply_progress_epoch == self._progress_epoch
            and _reply_similarity(self._last_no_progress_reply, reply)
            >= self.similarity_threshold
        )
        self.no_progress_repeat_count = (
            self.no_progress_repeat_count + 1 if similar else 1
        )
        self._last_no_progress_reply = reply
        self._last_reply_progress_epoch = self._progress_epoch
        if self.no_progress_repeat_count >= self.repeat_limit:
            return "clarification_loop"
        return None

    def record_tool_result(
        self, step: int, response: dict[str, Any]
    ) -> None:
        if response.get("ok"):
            self._successful_tool_steps.add(step)
            self._record_progress()

    def end_step(self, step: int) -> None:
        if (
            self._release_warning_step is not None
            and step > self._release_warning_step
            and step in self._successful_tool_steps
        ):
            self._release_warning_step = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "max_ask_user": self.max_ask_user,
            "ask_user_count": self.ask_count,
            "repeat_limit": self.repeat_limit,
            "reply_similarity_threshold": self.similarity_threshold,
            "no_progress_repeat_count": self.no_progress_repeat_count,
            "required_field_count": len(self.required_fields),
            "released_required_field_count": len(
                self.required_fields & self.released_fields
            ),
            "required_fields_released": self.required_fields_released,
        }

    def _record_progress(self) -> None:
        self._progress_epoch += 1
        self.no_progress_repeat_count = 0
        self._last_no_progress_reply = None
        self._last_reply_progress_epoch = -1
