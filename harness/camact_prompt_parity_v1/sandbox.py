"""Expose the isolated album at the exact source path in the shared prompt."""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath


def memory_alias_mounts(workspace: Path) -> list[str]:
    """Return one read-only album alias, without exposing any host parent tree.

    Old synthetic workspaces do not have a prompt policy and need no alias.
    An existing but invalid policy must fail closed before starting the CLI.
    The source is always the task's isolated copy, never ``memory_root``.
    """
    policy_path = workspace / ".camact" / "prompt_policy.json"
    if not policy_path.exists() and not policy_path.is_symlink():
        return []
    if policy_path.is_symlink() or policy_path.parent.is_symlink():
        raise ValueError("Prompt policy must be a task-local regular file")
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    if not isinstance(policy, dict) or policy.get("schema_version") != "camact.system_prompt_policy.v1":
        raise ValueError("Invalid CamAct system prompt policy")

    root = policy.get("memory_root")
    if not isinstance(root, str) or "\\" in root or "\x00" in root:
        raise ValueError("Memory alias requires an absolute Linux path")
    target = PurePosixPath(root)
    if (not target.is_absolute() or root.startswith("//") or str(target) != root
            or ".." in target.parts or len(target.parts) < 5
            or target.parts[-3] != "users" or target.name != "base_memory"):
        raise ValueError("Memory alias must identify exactly one user's base_memory")
    if target.parts[1] in {"usr", "bin", "sbin", "lib", "lib64", "etc", "dev", "proc", "sys", "run", "opt", "transport"}:
        raise ValueError("Memory alias cannot shadow a sandbox system path")

    album = workspace / "album"
    if album.is_symlink() or not album.is_dir():
        raise ValueError("Memory alias source must be the isolated task album")
    return ["--ro-bind", str(album.resolve(strict=True)), root]
