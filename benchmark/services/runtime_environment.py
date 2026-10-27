"""Stateful, per-trial task environment for CamAct agent evaluation.

The environment materializes static task fixtures into an isolated writable
session directory.  Agent tool calls are executed immediately against that
state and return observations that can influence subsequent calls.  The
evaluator consumes the resulting audit trail and final state; it never needs
to replay agent-declared actions.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

from .tool_schema import validate_arguments
from .local_tools import LocalToolExecutor
from .tool_support import (ToolExecutionError, _load, _dump, _utc_now, _private_semantic_paths, _enforce_runtime_boundary, _parse_datetime)
from .instruction_user_simulator import (
    POLICY as INSTRUCTION_POLICY, STOP as SIMULATOR_STOP, MessageGenerator, validate_config,
    respond as instruction_simulator_respond,
)
from .simulator_common import SimulatorInfrastructureError
from .task_definition import load_task
from .fixtures import initial_state
from .service_manager import ServiceManager, ServiceInfrastructureError
from .platform_registry import TOOL_SERVICE
from .episode import VERSION
from threading import RLock
import weakref


from .api import (
    album_contact_sheet_data_url,
    image_data_url,
    inspect_image,
    metadata_lookup,
    owner_profile,
    owner_profile_data_url,
    people_search,
    person_record,
    person_reference,
    person_reference_data_url,
    photo_search_page,
    relationship_lookup,
)


AGENT_TASK_FIELDS = ("task_id", "task_type", "interaction_type", "user_query")
ALBUM_VISION_TOOLS = {"image_view", "inspect_image"}
ALBUM_BROWSE_TOOLS = {"album_browse"}
REFERENCE_VISION_TOOLS = {"person_view_reference"}
OWNER_VISION_TOOLS = {"owner_profile_view"}
VISION_TOOLS = ALBUM_VISION_TOOLS | REFERENCE_VISION_TOOLS | OWNER_VISION_TOOLS
DEFAULT_MAX_AGENT_TURNS = 50
DEFAULT_MAX_SIMULATOR_ROUNDS = 10
# Deprecated import alias; there is only one effective simulator budget.
DEFAULT_MAX_SIMULATOR_TURNS = DEFAULT_MAX_SIMULATOR_ROUNDS


class AgentTurnLimit(RuntimeError):
    reason = "agent_turn_limit_exceeded"


class SimulatorRoundLimit(RuntimeError):
    reason = "simulator_round_limit_exceeded"


SimulatorTurnLimit = SimulatorRoundLimit  # Deprecated exception name.


def _image_observation(image_id: str, data_url: Any) -> dict[str, Any] | None:
    """Audit the actual raw-image payload without retaining its base64 bytes."""
    if not isinstance(data_url, str) or not data_url.startswith("data:image/"):
        return None
    header, separator, encoded = data_url.partition(";base64,")
    if not separator:
        return None
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not payload:
        return None
    return {"image_id": image_id, "media_type": header[5:], "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest()}


def agent_task_view(spec: dict[str, Any]) -> dict[str, Any]:
    """Project a private construction spec onto the runtime-visible task fields."""
    return {
        key: copy.deepcopy(spec[key])
        for key in AGENT_TASK_FIELDS
        if key in spec
    }


def _image_names(value: Any) -> set[str]:
    if isinstance(value, str):
        return set(re.findall(r"\b[0-9]+\.(?:jpg|png)\b", value, flags=re.I))
    if isinstance(value, list):
        result: set[str] = set()
        for item in value:
            result.update(_image_names(item))
        return result
    if isinstance(value, dict):
        result = set()
        for item in value.values():
            result.update(_image_names(item))
        return result
    return set()


def _normalize_raw_image_values(values: Any) -> Any:
    """Accept comma-delimited image IDs in finish evidence as separate IDs."""
    if not isinstance(values, list):
        return values
    normalized: list[Any] = []
    for value in values:
        if not isinstance(value, str):
            normalized.append(value)
            continue
        normalized.extend(part.strip() for part in value.split(",") if part.strip())
    return normalized


class RuntimeEnvironment:
    """One isolated, stateful execution environment for one task trial."""

    def __init__(
        self,
        task_dir: Path,
        session_dir: Path,
        session_id: str | None = None,
        simulator_generator: MessageGenerator | None = None,
        max_simulator_turns: int | None = None,
        *,
        max_agent_turns: int = DEFAULT_MAX_AGENT_TURNS,
        max_simulator_rounds: int | None = None,
    ):
        self.task_dir = task_dir.resolve()
        self.session_dir = session_dir.resolve()
        self.session_id = session_id or uuid4().hex
        self.task = load_task(self.task_dir)
        if max_simulator_rounds is not None and max_simulator_turns is not None and max_simulator_rounds != max_simulator_turns:
            raise ValueError("max_simulator_turns is an alias; conflicting simulator round limits")
        task_limit = self.task.user_agent.max_rounds if self.task.user_agent_enabled else None
        self.max_simulator_rounds = next(value for value in (max_simulator_rounds, max_simulator_turns, task_limit, DEFAULT_MAX_SIMULATOR_ROUNDS) if value is not None)
        self.max_agent_turns = max_agent_turns
        for name in ("max_agent_turns", "max_simulator_rounds"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.task_type = self.task.task_type
        self.tools = {tool.name: tool.model_dump(exclude={"name"}) for tool in self.task.tools}
        # Keep the existing string argument/schema and all task files intact.
        # References are issued only by this Runtime instance's successful pages.
        self._album_page_count = 0
        self._album_image_refs: dict[str, str] = {}
        if "image_view" in self.tools:
            definition = self.tools["image_view"]
            image_schema = definition["input_schema"]["properties"]["image_id"]
            image_schema["description"] = (
                "Exact raw image filename or image_ref shown by album_browse "
                "in this session (for example p3-17)."
            )
        self.spec = _load(self.task_dir / "task_spec.json") if (self.task_dir / "task_spec.json").exists() else {}
        self.initial_message = self.task.initial_user_message()
        # Public values are derived from the execution contract, never hidden spec fields.
        self.spec.update(task_id=self.task.task_id, task_type=self.task_type,
                         interaction_type=self.task_type, user_query=self.initial_message["content"])
        self.history = {"mode": self.task_type, "messages": self.task.initial_messages()[:-1]}
        self.fixtures = self.task.load_fixtures(self.task_dir)
        self.simulator = self.task.user_agent.simulator_config() if self.task.user_agent_enabled else None
        self.simulator_generator = simulator_generator if self.simulator else None
        self.state = initial_state(self.fixtures, self.session_id, self.task_dir.name)
        self.state["session"].update(agent_turns=0, max_agent_turns=self.max_agent_turns,
                                     simulator_rounds=0, max_simulator_rounds=self.max_simulator_rounds if self.simulator else None)
        if self.simulator:
            self.state["user_simulator"] = {"stopped": False, "turns": []}
        self.audit: list[dict[str, Any]] = []
        self.simulator_audit: list[dict[str, Any]] = []
        self.conversation_trace = self.task.initial_messages()
        self.service_snapshots: dict[str, Any] = {}
        self.service_manager = None
        self._closed = False
        self._lock = RLock()
        self.session_dir.mkdir(parents=True, exist_ok=False)
        (self.session_dir / "workspace" / "output").mkdir(parents=True, exist_ok=True)
        try:
            _dump(self.session_dir / "context.json", self.agent_context())
            if self.task.services:
                self.service_manager = ServiceManager(self.task, self.task_dir, self.session_dir, self.session_id, self.state)
                self.service_manager.__enter__()
                self._finalizer = weakref.finalize(self, self.service_manager.close)
                self._sync_services()
            self._persist()
        except BaseException:
            if self.service_manager:
                self.service_manager.close()
            raise

    def initial_messages(self) -> list[dict[str, str]]:
        """Actual role-preserving messages to restore before the first inference."""
        return self.task.initial_messages()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type and self.state["session"]["status"] == "running":
            self.state["session"]["status"] = "infrastructure_error" if isinstance(exc_val, (ServiceInfrastructureError, SimulatorInfrastructureError)) else "error"
        self.close()

    def _sync_services(self) -> None:
        if self.service_manager and not self.service_manager.closed:
            snapshots = self.service_manager.snapshot()
            for document in snapshots.values():
                for key, value in document["state"].items():
                    self.state[key] = copy.deepcopy(value)
            self.service_snapshots = snapshots

    def agent_context(self) -> dict[str, Any]:
        """Return only agent-visible task data; hidden fixture facts stay private."""
        context = {
            "session_id": self.session_id,
            "task": agent_task_view(self.spec),
            "initial_message": self.initial_message,
            "conversation": {
                "mode": self.history.get("mode", "single_turn"),
                "messages": self.history.get("messages", []),
                "user_simulator_available": self.simulator is not None,
            },
            "tools": self.tools,
            "protocol": {
                "tool": {"op": "tool", "tool": "<declared tool>", "arguments": {}},
                "agent_generation": {"op": "agent_turn"},
                "clarify": {"op": "user_message", "content": "<question to user>"},
                "finish": {
                    "op": "finish",
                    "final_response": "<answer>",
                    "evidence": ["<raw image filename>"],
                },
            },
        }
        _enforce_runtime_boundary(context, "agent context")
        return context

    def _persist(self) -> None:
        _dump(self.session_dir / "state.json", self.state)
        _dump(self.session_dir / "conversation.json", self.conversation_trace)
        audit_path = self.session_dir / "audit.jsonl"
        audit_path.write_text(
            "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in self.audit),
            encoding="utf-8",
        )
        simulator_audit_path = self.session_dir / "simulator_audit.jsonl"
        simulator_audit_path.write_text(
            "".join(
                json.dumps(item, ensure_ascii=False) + "\n"
                for item in self.simulator_audit
            ),
            encoding="utf-8",
        )

    def _record(
        self,
        *,
        kind: str,
        name: str,
        request: dict[str, Any],
        response: Any,
        status: str,
        error: str | None = None,
        dispatch: dict | None = None,
        image_observation: dict | None = None,
    ) -> dict[str, Any]:
        event = {
            "sequence": len(self.audit) + 1,
            "timestamp": _utc_now(),
            "kind": kind,
            "name": name,
            "request": copy.deepcopy(request),
            "response": copy.deepcopy(response),
            "status": status,
        }
        if kind == "tool_call":
            # Evidence only: a raw image returned in a tool batch is available
            # to the next Agent generation, not to later calls in that batch.
            # Task-local graders may use this to check inspection timing.
            event["agent_turn"] = self.agent_turns
        if dispatch:
            event["dispatch"] = copy.deepcopy(dispatch)
        if image_observation is not None:
            event["image_observation"] = copy.deepcopy(image_observation)
        if error:
            event["error"] = error
        self.audit.append(event)
        self._persist()
        return event


    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            return self._call_tool(name, arguments)

    def _call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute one agent tool call and return its immediate observation."""
        arguments = {} if arguments is None else arguments
        if self._closed:
            raise ToolExecutionError("episode is closed")
        committed_state = self.state
        dispatch = {}
        image_observation = None
        executor = None
        page_refs = {}
        try:
            if name not in self.tools:
                raise ToolExecutionError(f"tool '{name}' is not declared for this task")
            validate_arguments(name, self.tools[name], arguments)
            # Only image_view accepts session-issued thumbnail references.
            # Business arguments retain the declared service schema and exact
            # Agent request; grading projections never change dispatch input.
            execution_arguments = arguments
            image_ref = None
            if name == "image_view":
                requested = arguments.get("image_id", "")
                if requested in self._album_image_refs:
                    image_ref = requested
                    execution_arguments = {**arguments, "image_id": self._album_image_refs[requested]}
                elif re.fullmatch(r"p[0-9]+-[0-9]+", requested):
                    raise ToolExecutionError(f"unknown album image_ref: {requested}")
            if name in self.task.get_endpoint_map():
                response, dispatch = self.service_manager.dispatch(name, execution_arguments)
                self._sync_services()
                if dispatch["response_status"] >= 400:
                    raise ToolExecutionError(response.get("error", "service rejected action"))
            else:
                if name in TOOL_SERVICE:
                    raise ToolExecutionError(f"stateful tool '{name}' has no service endpoint")
                self.state = copy.deepcopy(committed_state)
                executor = LocalToolExecutor(self.task_dir, self.session_dir, self.state)
                response = executor.prepare(name, execution_arguments, self.tools[name])
            if image_ref is not None:
                response["image_ref"] = image_ref
            _enforce_runtime_boundary(response, f"tool '{name}' observation")
            observation = {"ok": True, "tool": name, "result": response}
            if name in ALBUM_BROWSE_TOOLS:
                photos = list(response.get("photos", []))
                page_ref = f"p{self._album_page_count + 1}"
                response["page_ref"] = page_ref
                for index, photo in enumerate(photos, 1):
                    photo["image_ref"] = f"{page_ref}-{index}"
                    page_refs[photo["image_ref"]] = photo["image"]
                response["image_refs"] = page_refs
                page_start = int(response.get("offset", 0)) + 1
                page_end = int(response.get("offset", 0)) + len(photos)
                observation["content"] = [
                    {
                        "type": "text",
                        "text": (
                            f"Chronological album thumbnails {page_start}-{page_end} "
                            f"of {response.get('total', 0)}. Thumbnails match result.photos "
                            "in order, left to right then top to bottom, starting with "
                            "result.photos[0]. Each thumbnail is labeled with its image_ref; "
                            "the same reference and raw filename appear in result.photos and "
                            "result.image_refs. To inspect a selected thumbnail, pass its exact "
                            "short label as image_view.image_id (for example p3-17). References "
                            "include the page prefix and stay valid in this session; never omit "
                            "or change that prefix. Raw filenames remain supported. The view "
                            "returns the resolved raw image_id for subsequent business tools. "
                            "Use image_view for full-resolution inspection."
                        ),
                    }
                ]
                if photos:
                    observation["content"].append(
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": album_contact_sheet_data_url(self.task_dir, photos),
                                "detail": "auto",
                            },
                        }
                    )
            elif name in ALBUM_VISION_TOOLS:
                image_id = str(response["image_id"])
                data_url = image_data_url(self.task_dir, image_id)
                image_observation = _image_observation(image_id, data_url)
                observation["content"] = [
                    {
                        "type": "text",
                        "text": f"Raw runtime image observation for {image_id}.",
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": data_url,
                            "detail": "auto",
                        },
                    },
                ]
            elif name in REFERENCE_VISION_TOOLS:
                person_id = str(response["person_id"])
                observation["content"] = [
                    {
                        "type": "text",
                        "text": f"Reference portrait for {response['display_name']} ({person_id}).",
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": person_reference_data_url(self.task_dir, person_id),
                            "detail": "auto",
                        },
                    },
                ]
            elif name in OWNER_VISION_TOOLS:
                person_id = str(response["person_id"])
                observation["content"] = [
                    {
                        "type": "text",
                        "text": (
                            "Owner identity reference for "
                            f"{response['display_name']} ({person_id})."
                        ),
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": owner_profile_data_url(self.task_dir),
                            "detail": "auto",
                        },
                    },
                ]
            if executor is not None:
                executor.commit_files()
                committed_state.clear()
                committed_state.update(self.state)
                self.state = committed_state
            self._record(
                kind="tool_call",
                name=name,
                request=arguments if name == "image_view" else execution_arguments,
                response=response,
                status="succeeded",
                dispatch=dispatch,
                image_observation=image_observation,
            )
            if name in ALBUM_BROWSE_TOOLS:
                self._album_page_count += 1
                self._album_image_refs.update(page_refs)
            return observation
        except (KeyError, ToolExecutionError, TypeError, ValueError) as exc:
            self.state = committed_state
            message = str(exc)
            response = {"error": message}
            self._record(
                kind="tool_call",
                name=name,
                request=arguments if name == "image_view" else execution_arguments,
                response=response,
                status="rejected",
                error=message,
                dispatch=dispatch,
            )
            return {"ok": False, "tool": name, "error": message}
        except ServiceInfrastructureError as exc:
            self.state = committed_state
            self.state["session"]["status"] = "infrastructure_error"
            self._record(kind="tool_call", name=name, request=arguments,
                         response={"error": str(exc)}, status="infrastructure_error",
                         error=str(exc), dispatch=exc.dispatch or dispatch)
            raise
        except BaseException:
            self.state = committed_state
            raise

    @property
    def instruction_simulator(self) -> bool:
        return bool(self.simulator and self.simulator.get("policy") == INSTRUCTION_POLICY)

    @property
    def simulator_stopped(self) -> bool:
        return self.instruction_simulator and bool(self.state["user_simulator"].get("stopped"))

    def record_assistant_message(self, content: str) -> None:
        if content.strip():
            self.conversation_trace.append({"role": "assistant", "content": content})

    @property
    def agent_turns(self) -> int:
        return self.state["session"]["agent_turns"]

    @property
    def simulator_rounds(self) -> int:
        return self.state["session"]["simulator_rounds"]

    @property
    def max_simulator_turns(self) -> int:
        """Deprecated alias for integrations; never an additional cap."""
        return self.max_simulator_rounds

    def begin_agent_turn(self) -> int:
        """Count one logical Agent generation before invoking its provider.

        The provider may retry HTTP internally; tools and simulator calls never
        call this method. The last allowed generation is processed completely,
        including STOP, before a subsequent generation can exceed the limit.
        """
        if self.agent_turns >= self.max_agent_turns:
            self._budget_limit(AgentTurnLimit)
        self.state["session"]["agent_turns"] += 1
        self._persist()
        return self.agent_turns

    def user_message(self, content: str) -> dict[str, Any]:
        """Send an Agent message to the task's configured user simulator."""
        content = str(content).strip()
        if not content:
            raise ToolExecutionError("user message must not be empty")
        if self.simulator_stopped:
            raise ToolExecutionError("user conversation has already ended")
        if self.simulator is None:
            self.conversation_trace.append({"role": "assistant", "content": content})
            response = {"error": "this task has no user simulator"}
            self._record(
                kind="user_turn",
                name="user_message",
                request={"content": content},
                response=response,
                status="rejected",
                error=response["error"],
            )
            return {"ok": False, **response}

        if self.simulator_rounds >= self.max_simulator_rounds:
            self._budget_limit(SimulatorRoundLimit)
        self.conversation_trace.append({"role": "assistant", "content": content})
        try:
            response = instruction_simulator_respond(
                self.simulator, self.state["user_simulator"], self.conversation_trace,
                task_id=self.task.task_id, generator=self.simulator_generator,
            )
        except SimulatorInfrastructureError as exc:
            from .simulator_common import SimulatorProtocolError
            if isinstance(exc, SimulatorProtocolError):
                # Private failure evidence; no user reply or STOP is delivered.
                import os
                path = self.session_dir / "simulator_protocol_errors.jsonl"
                raw = exc.raw_response
                row = {"timestamp": _utc_now(), "session_id": self.session_id,
                       "task_id": self.task.task_id, "reason": exc.reason,
                       "simulator_rounds": self.simulator_rounds, "raw_response": raw,
                       "response_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest()}
                with path.open("a", encoding="utf-8") as stream:
                    path.chmod(0o600)
                    stream.write(json.dumps(row, ensure_ascii=False) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            self._persist()
            raise
        self.simulator_audit.append(copy.deepcopy(response.pop("audit")))
        response.pop("stopped")  # Runtime control only: never expose STOP/state to the agent.
        if self.simulator_stopped:
            # Existing graders reserve termination_reason for failures.
            self.state["session"]["completion_reason"] = "simulator_stop"
        if response["content"]:
            # Claw-Eval user_agent_rounds: count a generated user reply, not STOP,
            # failed generation, tool execution or individual transport retries.
            self.state["session"]["simulator_rounds"] += 1
            self.conversation_trace.append({"role": "user", "content": response["content"]})
        self._record(
            kind="user_turn",
            name="user_message",
            request={"content": content},
            response=response,
            status="succeeded",
        )
        if not self.simulator_stopped and self.simulator_rounds >= self.max_simulator_rounds:
            self._budget_limit(SimulatorRoundLimit)
        return {"ok": True, **response}

    def _budget_limit(self, limit_type) -> None:
        self.state["session"].update(status="agent_failure", termination_reason=limit_type.reason,
                                     failure_type=limit_type.reason,
                                     strict_success=False)
        self._persist()
        raise limit_type(limit_type.reason)

    def tool_calls_for_evaluation(self) -> list[dict[str, Any]]:
        return [
            {
                "tool": event["name"],
                "arguments": event["request"],
                "status": event["status"],
            }
            for event in self.audit
            if event["kind"] == "tool_call"
        ]

    def execution_trace(self) -> list[dict[str, Any]]:
        """Lossless tool evidence with a public projection of simulator turns."""
        trace = []
        for event in self.audit:
            public = {key: copy.deepcopy(event[key]) for key in (
                "sequence", "timestamp", "kind", "name", "request", "response", "status", "error", "dispatch", "agent_turn", "image_observation"
            ) if key in event}
            if event.get("kind") == "user_turn":
                public["response"] = {"content": event.get("response", {}).get("content", "")}
            trace.append(public)
        return trace

    def snapshot(self, *, terminal: bool = False) -> dict[str, Any]:
        with self._lock:
            self._sync_services()
            if terminal:
                if self.state["session"]["status"] == "running":
                    self.state["session"]["status"] = "finished"
                self.state["session"].setdefault("finished_at", _utc_now())
                _dump(self.session_dir / "grader_fixture.json", self.fixtures)
                if self.service_manager and not self.service_manager.closed:
                    self.service_manager.record_snapshot(self.service_snapshots)
            self._persist()
            return copy.deepcopy(self.state)

    def build_submission(self, final_response: str, evidence: list[str] | None = None) -> dict:
        evidence = _normalize_raw_image_values(evidence or [])
        evidence = [self._album_image_refs.get(value, value) if isinstance(value, str) else value
                    for value in evidence]
        LocalToolExecutor(self.task_dir, self.session_dir, self.state)._require_images(evidence)
        final_response = str(final_response)
        if final_response.strip() and (not self.conversation_trace or self.conversation_trace[-1] != {"role": "assistant", "content": final_response}):
            self.record_assistant_message(final_response)
        state = self.snapshot(terminal=True)
        return self._save_episode(final_response, evidence, state)

    def _save_episode(self, final_response: str, evidence: list[str], state: dict, *, snapshot_complete: bool = True) -> dict:
        # The legacy names remain as aliases for existing CamAct graders/adapters.
        trace = self.execution_trace()
        environment = {key: value for key, value in state.items() if key != "user_simulator"}
        simulator_state = state.get("user_simulator", {})
        turns = simulator_state.get("turns", [])
        last_turn = turns[-1] if turns else {}
        submission = {
            "task_id": self.task.task_id,
            "status": state["session"]["status"],
            "final_answer": final_response, "final_response": final_response,
            "evidence": list(evidence), "tool_calls": self.tool_calls_for_evaluation(), "actions": [],
            "conversation": copy.deepcopy(self.conversation_trace),
            "conversation_trace": copy.deepcopy(self.conversation_trace),
            "execution_trace": trace, "action_audit": copy.deepcopy(trace),
            "final_environment": environment,
            # Evaluator-only envelope; never exposed through agent_context.
            "evaluator_private_state": {
                "session_id": self.session_id,
                "task_id": self.task.task_id,
                "user_simulator": copy.deepcopy(simulator_state),
            },
            "final_service_state": {name: copy.deepcopy(doc["state"]) for name, doc in self.service_snapshots.items()},
            "service_audit": {name: copy.deepcopy(doc["audit"]) for name, doc in self.service_snapshots.items()},
            "runtime_metadata": {
                "episode_contract": VERSION,
                "task_type": self.task_type, "session_id": self.session_id,
                "services": [service.name for service in self.task.services],
                "user_simulator_enabled": self.simulator is not None,
                # Keep terminal control evidence when adapters strip private state.
                # No hidden instructions or unasked preferences enter this projection.
                **({"simulator_stop": {
                    "state_closed": simulator_state.get("stopped") is True,
                    "stop_token_returned": last_turn.get("response") == SIMULATOR_STOP
                    and last_turn.get("stopped") is True,
                }} if self.simulator is not None else {}),
                "status": state["session"]["status"],
                "snapshot_complete": snapshot_complete,
                "evaluator_config": self.task.evaluator_config,
                **{key: state["session"].get(key) for key in (
                    "agent_turns", "max_agent_turns", "simulator_rounds", "max_simulator_rounds",
                    "termination_reason", "failure_type", "completion_reason")},
            },
            "identity_claims": self._state_identity_claims(),
            "execution_mode": "stateful_runtime", "session_id": self.session_id,
        }
        _dump(self.session_dir / "episode.json", submission)
        return submission

    def close(self) -> dict[str, Any]:
        if self._closed:
            return copy.deepcopy(self.state)
        try:
            state = self.snapshot(terminal=True)
            if not (self.session_dir / "episode.json").exists():
                self._save_episode("", [], state)
            return state
        except Exception as exc:
            self.state["session"].update(status="infrastructure_error", error=f"snapshot failed ({type(exc).__name__})")
            self._persist()
            try:
                previous = _load(self.session_dir / "episode.json")
            except (OSError, ValueError):
                previous = {}
            self._save_episode(previous.get("final_answer", ""), previous.get("evidence", []),
                               copy.deepcopy(self.state), snapshot_complete=False)
            raise
        finally:
            self._closed = True
            if self.service_manager:
                self.service_manager.close()

    def _state_identity_claims(self) -> list[dict[str, Any]]:
        claims: list[dict[str, Any]] = []
        records = (
            list(self.state["messages"]["sent"])
            + list(self.state["publishing"]["drafts"]["created"])
            + list(self.state["workspace"]["output"])
        )
        for record in records:
            for claim in record.get("identity_claims", []):
                if claim not in claims:
                    claims.append(copy.deepcopy(claim))
        return claims


