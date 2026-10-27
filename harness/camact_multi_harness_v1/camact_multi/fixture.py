"""Explicit synthetic fixture, never a canonical CamAct task or model evaluation."""
from pathlib import Path
import json
from claude_code_harness.core import TaskHandle, write_json

def create(root: Path):
    import yaml
    from PIL import Image
    from benchmark.services.platform_registry import service_contract
    root.mkdir(parents=True, exist_ok=False)
    memory = root / "users/fixture_user/base_memory"
    (memory / "images").mkdir(parents=True)
    Image.new("RGB", (32, 32), (40, 130, 190)).save(memory / "images/1001.png")
    (memory / "metadata.csv").write_text("image,datetaken,location\n1001.png,2026-01-01,fixture\n")
    task_dir = root / "tasks/fixture_user/task_fixture"
    task_dir.mkdir(parents=True)
    tools = [
        {"name": "message_create_draft", "description": "Create an offline fixture draft",
         "input_schema": {"type": "object", "properties": {"to": {"type": "string"}, "text": {"type": "string"},
            "attachments": {"type": "array", "items": {"type": "string"}}}, "required": ["to", "text", "attachments"], "additionalProperties": False}},
        {"name": "image_view", "description": "Fixture domain capability, disabled for native mode",
         "input_schema": {"type": "object", "properties": {"image_id": {"type": "string"}}, "required": ["image_id"]}}]
    services, endpoints = service_contract([t["name"] for t in tools])
    component = {"id": "fixture:draft", "owner": "fixture:draft", "description": "Synthetic draft persisted",
                 "dimension": "outcome_correctness", "weight": 1.0, "mandatory": True,
                 "check": {"type": "deterministic", "checker": "fixture_draft", "params": {}},
                 "evidence_requirements": {"source": "final_service_state"}, "score_values": [0, 1]}
    task = {"task_id": "fixture_user_OFFLINE", "task_type": "multi_turn",
            "prompt": {"text": "Offline fixture: ask the recipient, then create one draft with 1001.png."},
            "tools": tools, "services": services, "tool_endpoints": endpoints, "fixtures": ["workspace/state.json"],
            "user_agent": {"enabled": True, "persona": "Synthetic fixture only. Recipient is Fixture Recipient."},
            "scoring_contract": "camact.atomic.v3", "scoring_components": [component],
            "dimension_weights": {"outcome_correctness": 1.0}, "grader": "grader.py",
            "reference_solution": {"fixture_only": True}, "safety_checks": []}
    (task_dir / "task.yaml").write_text(yaml.safe_dump(task, sort_keys=False))
    write_json(task_dir / "task_spec.json", {"task_id": task["task_id"], "scoring_contract": "camact.atomic.v3"})
    write_json(task_dir / "workspace/state.json", {"contacts": [{"contact_id": "contact_fixture", "name": "Fixture Recipient"}], "messaging": {"threads": [], "drafts": []}})
    write_json(task_dir / "workspace/memory_snapshot/memory_manifest.json", {"runtime_root": str(memory)})
    (task_dir / "grader.py").write_text('''from benchmark.evaluator.grading import GradingResult, _result
TASK_ID = 'fixture_user_OFFLINE'
class TaskGrader:
    def grade(self, *, task, submission, state, judge):
        drafts = state['messages']['drafts']
        passed = len(drafts) == 1 and drafts[0]['attachments'] == ['1001.png'] and not state['messages']['sent']
        return GradingResult(criteria=[_result(task['scoring_components'][0], passed,
            ['final_service_state/messages'], 'Synthetic fixture state and receipt check')])
''')
    return TaskHandle("fixture_user", "task_fixture", task_dir, task["task_id"])

