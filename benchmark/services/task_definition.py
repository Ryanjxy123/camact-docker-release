"""CamAct task loading, following Claw-Eval TaskDefinition/ToolSpec/ServiceDef.

Claw-Eval reference: models/task.py and models/tool.py at 5680b8b11ff2ee5d.
See ../THIRD_PARTY_NOTICES.md. Task content, GT and rubric remain intact; type labels use the current taxonomy.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

from .instruction_user_simulator import POLICY, STOP, validate_config
from .tool_schema import input_schema, schema_validator
from .history_context import HISTORY_GUIDANCE, history_tool_defaults, saved_history_thread


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Prompt(ContractModel):
    text: str = Field(min_length=1)


class ToolSpec(ContractModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any]


class ToolEndpoint(ContractModel):
    tool_name: str
    url: str
    method: Literal["POST", "GET"] = "POST"


class ServiceDef(ContractModel):
    name: str
    command: str
    port: int = Field(ge=1, le=65535)
    health_check: str
    health_check_method: Literal["POST", "GET"] = "GET"
    ready_timeout: float = Field(default=10.0, gt=0)
    reset_endpoint: str
    env: dict[str, str] = Field(default_factory=dict)

    @property
    def audit_endpoint(self) -> str:
        return self.reset_endpoint.rsplit("/reset", 1)[0] + "/audit"


class TaskContext(ContractModel):
    model_config = ConfigDict(extra="forbid", strict=True, json_schema_extra={
        "allOf": [
            {"required": ["source", "thread_id"], "properties": {
                "source": {"enum": ["messages", "mail", "chat"]},
                "thread_id": {"type": "string", "minLength": 1, "pattern": "\\S"}}},
            {"if": {"properties": {"kind": {"const": "agent_history"}}, "required": ["kind"]},
             "then": {"properties": {"source": {"const": "messages"}}}},
            {"if": {"properties": {"kind": {"const": "external_conversation"}}, "required": ["kind"]},
             "then": {"properties": {"messages": {"maxItems": 0}}}},
        ],
    })
    kind: Literal["agent_history", "external_conversation"]
    messages: list[dict[str, str]] = Field(default_factory=list)
    source: Literal["messages", "mail", "chat"] | None = None
    thread_id: str | None = None

    @model_validator(mode="after")
    def validate_source(self):
        if self.kind == "agent_history":
            for message in self.messages:
                if set(message) != {"role", "content"} or message["role"] not in {"user", "assistant"} or not message["content"].strip():
                    raise ValueError("agent_history needs user/assistant text messages")
            if self.source != "messages" or not self.thread_id or not self.thread_id.strip():
                raise ValueError("agent_history needs a Messages source/thread_id")
        elif self.messages or self.source is None or not self.thread_id or not self.thread_id.strip():
            raise ValueError("external_conversation needs source/thread_id and no inline messages")
        return self


class UserAgentTaskConfig(ContractModel):
    """Claw-Eval's task-owned settings, with CamAct's 10-round default."""

    enabled: bool = False
    persona: str = Field(default="", validation_alias=AliasChoices("persona", "hidden_instruction"))
    max_rounds: int = Field(default=10, ge=1)
    # Public interaction guidance only; never derive this from persona or GT.
    system_prompt_suffix: str = ""

    @field_validator("max_rounds", mode="before")
    @classmethod
    def legacy_default_rounds(cls, value):
        return 10 if value is None else value

    @model_validator(mode="after")
    def validate_persona(self):
        if self.enabled and not self.persona.strip():
            raise ValueError("enabled user_agent requires a non-empty persona")
        return self

    @property
    def hidden_instruction(self) -> str:
        """Read compatibility for integrations; serialized once as persona."""
        return self.persona

    def simulator_config(self) -> dict[str, Any]:
        config = {"policy": POLICY, "user_instruction": self.persona,
                  "user_agent": {"strategy": "llm", "stop_token": STOP}}
        validate_config(config)
        return config


UserAgentConfig = UserAgentTaskConfig  # Existing imports remain valid.


def scoring_references(task_dir: Path) -> list[dict[str, Any]]:
    """Return an authored contract, with legacy references for tool-only fixtures."""
    task_path = task_dir / "task.yaml"
    if task_path.exists():
        authored = yaml.safe_load(task_path.read_text(encoding="utf-8"))
        if authored.get("scoring_contract"):
            return authored["scoring_components"]
    config_path = task_dir / "evaluator_config.json"
    if not config_path.exists():
        return []  # Small tool-only fixtures need no grader.
    config = json.loads(config_path.read_text(encoding="utf-8"))
    return [
        {"name": dimension, "weight": weight,
         "check": {"type": "camact_rubric", "config": "evaluator_config.json", "dimension": dimension}}
        for dimension, weight in config.get("dimension_weights", {}).items()
    ]


class TaskDefinition(ContractModel):
    task_id: str
    task_type: Literal["single_turn", "users_history", "multi_turn"]
    prompt: Prompt
    public_system_prompt_suffix: str = ""
    context: TaskContext | None = None
    tools: list[ToolSpec]
    services: list[ServiceDef] = Field(default_factory=list)
    tool_endpoints: list[ToolEndpoint] = Field(default_factory=list)
    fixtures: list[str] = Field(default_factory=list)
    user_agent: UserAgentTaskConfig | None = None
    # Task-owned scoring is consumed by its local grader, never by the runtime.
    scoring_components: list[dict[str, Any]] = Field(default_factory=list, json_schema_extra={
        "items": {"type": "object", "additionalProperties": True,
                  "properties": {"dimension": {"type": "string", "enum": [
                      "outcome_correctness", "context_grounding", "execution_state", "interaction_adaptation"]}},
                  "if": {"required": ["id"]}, "then": {"required": ["dimension"]}}
    })
    scoring_contract: Literal["camact.atomic.v2", "camact.atomic.v3"] | None = None
    dimension_weights: dict[str, float] = Field(default_factory=dict)
    grader: Literal["grader.py"] | None = None
    judge_rubric: str = ""
    reference_solution: dict[str, Any] = Field(default_factory=dict)
    safety_checks: list[dict[str, Any]] = Field(default_factory=list)
    evaluator_config: Literal["evaluator_config.json"] = "evaluator_config.json"
    _legacy_history: list[dict[str, str]] = PrivateAttr(default_factory=list)

    @model_validator(mode="wrap")
    @classmethod
    def default_history_tools(cls, data, handler):
        if not isinstance(data, dict):
            return handler(data)
        if isinstance(data.get("context"), TaskContext):
            data = {**data, "context": data["context"].model_dump()}
        data = history_tool_defaults(data)
        context = data.get("context")
        legacy = []
        if (data.get("task_type") == "users_history" and isinstance(context, dict)
                and context.get("kind") == "agent_history" and context.get("messages")):
            # Validate legacy records before storing them outside the serialized
            # public definition. The fixture loader alone can materialize them.
            TaskContext.model_validate(context)
            legacy = context.pop("messages")
        task = handler(data)
        task._legacy_history = copy.deepcopy(legacy)
        return task

    @model_validator(mode="after")
    def validate_contract(self):
        from .platform_registry import TOOL_SERVICE, TOOL_SERVICES
        if (self.task_type == "multi_turn") != self.user_agent_enabled:
            raise ValueError("only multi_turn tasks must enable user_agent")
        if (self.task_type == "users_history") != (self.context is not None):
            raise ValueError("only users_history tasks must declare context")
        names = [tool.name for tool in self.tools]
        service_names = [service.name for service in self.services]
        ports = [service.port for service in self.services]
        endpoint_names = [endpoint.tool_name for endpoint in self.tool_endpoints]
        for values in (names, service_names, ports, endpoint_names):
            if len(values) != len(set(values)):
                raise ValueError("duplicate tool/service/port/endpoint declaration")
        for tool in self.tools:
            schema_validator(tool.input_schema)
            if tool.input_schema.get("type") != "object":
                raise ValueError("tool input_schema must describe an object")
        used_services = set()
        for endpoint in self.tool_endpoints:
            if endpoint.tool_name not in names:
                raise ValueError("endpoint tool is not declared")
            service = self.service_for_endpoint(endpoint)
            if service.name not in TOOL_SERVICES.get(endpoint.tool_name, set()):
                raise ValueError("tool endpoint routes to the wrong platform service")
            used_services.add(service.name)
        if set(endpoint_names) != set(names) & set(TOOL_SERVICE):
            raise ValueError("every external platform tool needs its HTTP endpoint")
        if used_services != set(service_names):
            raise ValueError("every declared service needs a tool endpoint")
        for service in self.services:
            for url in (service.health_check, service.reset_endpoint):
                parsed = urlparse(url)
                if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1"} or parsed.port != service.port:
                    raise ValueError("service URLs must match its local logical port")
            if not service.reset_endpoint.endswith("/reset"):
                raise ValueError("reset_endpoint must end in /reset")
        if self.context:
            if not {"thread_get", "threads_list"} <= set(endpoint_names):
                raise ValueError("saved conversations need Messages read endpoints")
        return self

    def service_for_endpoint(self, endpoint: ToolEndpoint) -> ServiceDef:
        parsed = urlparse(endpoint.url)
        if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1"}:
            raise ValueError("mock tool endpoints must use local HTTP")
        for service in self.services:
            if parsed.port == service.port:
                return service
        raise ValueError("tool endpoint has no declared service")

    def get_endpoint_map(self) -> dict[str, ToolEndpoint]:
        return {endpoint.tool_name: endpoint for endpoint in self.tool_endpoints}

    @property
    def user_agent_enabled(self) -> bool:
        return self.user_agent is not None and self.user_agent.enabled

    @property
    def system_prompt_suffix(self) -> str:
        if self.task_type == "users_history":
            base = HISTORY_GUIDANCE
        else:
            base = self.user_agent.system_prompt_suffix if self.user_agent_enabled else ""
        return "\n\n".join(part for part in (base, self.public_system_prompt_suffix) if part)

    def initial_user_message(self) -> dict[str, str]:
        return {"role": "user", "content": self.prompt.text}

    def initial_messages(self) -> list[dict[str, str]]:
        return [self.initial_user_message()]

    def load_fixtures(self, task_dir: Path) -> dict[str, Any]:
        fixtures: dict[str, Any] = {}
        for relative in self.fixtures:
            path = task_path(task_dir, relative)
            data = json.loads(path.read_text(encoding="utf-8"))
            data = data.get("fixtures", data)
            if not isinstance(data, dict) or set(fixtures) & set(data):
                raise ValueError("fixtures must be disjoint structured objects")
            fixtures.update(copy.deepcopy(data))
        if self.context:
            messaging = fixtures.setdefault("messaging", {})
            if not isinstance(messaging, dict):
                raise ValueError("saved context needs a Messages fixture object")
            threads = messaging.setdefault("threads", [])
            if not isinstance(threads, list) or any(not isinstance(thread, dict) for thread in threads):
                raise ValueError("saved context needs a list of thread objects")
            matches = [thread for thread in threads if thread.get("thread_id") == self.context.thread_id]
            if self._legacy_history:
                if not matches:
                    thread = saved_history_thread(self._legacy_history, self.context.thread_id)
                    threads.append(thread)
                    matches = [thread]
                elif len(matches) == 1 and matches[0].get("messages") != self._legacy_history:
                    raise ValueError("inline saved history differs from the Messages fixture")
            if len(matches) != 1:
                raise ValueError("saved context needs exactly one matching thread in fixtures")
            messages = matches[0].get("messages")
            if not isinstance(messages, list) or not messages:
                raise ValueError("saved context thread must contain conversation records")
            if self.context.kind == "agent_history":
                for message in messages:
                    if (not isinstance(message, dict) or set(message) != {"role", "content"}
                            or message["role"] not in {"user", "assistant"}
                            or not isinstance(message["content"], str) or not message["content"].strip()):
                        raise ValueError("saved agent history needs original user/assistant text messages")
        return fixtures

    @classmethod
    def from_yaml(cls, path: str | Path) -> TaskDefinition:
        path = Path(path)
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return cls.model_validate(data)
        user_agent = data.get("user_agent") or {}
        # Normalize earlier CamAct YAML at the file boundary, before validation.
        # An explicit legacy source keeps its old precedence over a stale prompt.
        # Canonical tasks now have prompt.text and do not enter this branch.
        if isinstance(user_agent, dict) and data.get("task_type") == "multi_turn" and (
            "initial_message_file" in user_agent or "prompt" not in data
        ):
            relative = user_agent.pop("initial_message_file", "conversation/initial_message.json")
            message = _load_public_opening(path.parent, relative)
            data["prompt"] = {"text": message["content"]}
        return cls.model_validate(data)


def task_path(task_dir: Path, relative: str) -> Path:
    path = (task_dir / relative).resolve()
    if not path.is_relative_to(task_dir.resolve()):
        raise ValueError("task resource escapes task directory")
    return path


def _load_public_opening(task_dir: Path, relative: str = "conversation/initial_message.json") -> dict[str, str]:
    message = json.loads(task_path(task_dir, relative).read_text(encoding="utf-8"))
    if (not isinstance(message, dict) or set(message) != {"role", "content"}
            or message["role"] != "user" or not isinstance(message["content"], str)
            or not message["content"].strip()):
        raise ValueError("simulator initial message must contain only role=user and non-empty content")
    return message


def load_task(task_dir: Path) -> TaskDefinition:
    path = task_dir / "task.yaml"
    if path.exists():
        task = TaskDefinition.from_yaml(path)
    else:
        # Older fixtures/tests can be loaded through the exact same runtime.
        task = TaskDefinition.model_validate(legacy_contract(task_dir))
    task.load_fixtures(task_dir)
    if task.scoring_contract:
        try:
            from benchmark.evaluator.contracts import load_contract
        except ModuleNotFoundError:
            from evaluator.contracts import load_contract
        load_contract(task_dir)
    elif task.scoring_components != scoring_references(task_dir):
        raise ValueError("scoring_components must reference the unchanged canonical CamAct rubric/weights")
    return task


def legacy_contract(task_dir: Path) -> dict[str, Any]:
    def read(relative):
        return json.loads((task_dir / relative).read_text(encoding="utf-8"))
    from .platform_registry import service_contract
    spec = read("task_spec.json")
    history = read("conversation/history.json")
    definitions = read("tools.json")
    task_type = spec["interaction_type"]
    services, endpoints = service_contract(definitions)
    data = {
        "task_id": spec["task_id"], "task_type": task_type,
        "prompt": {"text": _load_public_opening(task_dir)["content"]},
        "tools": [{"name": name, "description": definition.get("description", ""), "input_schema": input_schema(definition)} for name, definition in definitions.items()],
        "services": services, "tool_endpoints": endpoints, "fixtures": ["workspace/state.json"],
        "scoring_components": scoring_references(task_dir),
        "evaluator_config": "evaluator_config.json",
    }
    if task_type == "users_history":
        if history.get("context_kind") == "external_conversation":
            data["context"] = {"kind": "external_conversation", "source": history["source"],
                               "thread_id": history["thread_id"]}
        elif history.get("messages"):
            data["context"] = {"kind": "agent_history", "messages": history["messages"]}
            if history.get("source") and history.get("thread_id"):
                data["context"].update(source=history["source"], thread_id=history["thread_id"])
        else:
            data["context"] = {"kind": "agent_history", "source": history.get("source"),
                               "thread_id": history.get("thread_id")}
    if task_type == "multi_turn":
        simulator = read("conversation/simulator.json")
        validate_config(simulator)
        data["user_agent"] = {"enabled": True, "persona": simulator["user_instruction"],
                              "max_rounds": 10, "system_prompt_suffix": ""}
    return data
