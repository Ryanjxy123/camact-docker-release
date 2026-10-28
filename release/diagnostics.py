"""Public diagnostics contain source locations and fixed categories, never values."""
from __future__ import annotations

import ast
import errno
from pathlib import Path
import re

PREFIX = "CAMACT_DIAGNOSTIC_JSON="
PHRASES = {
    "operation not permitted": "operation_not_permitted",
    "permission denied": "permission_denied",
    "read-only file system": "read_only_file_system",
    "no space left on device": "no_space_left",
    "unknown flag": "unknown_flag",
    "flag provided but not defined": "unknown_flag",
    "invalid argument": "invalid_argument",
    "no such file or directory": "missing_file",
    "failed to create sandbox": "sandbox_creation_failed",
    "creating sandbox": "sandbox_creation",
    "creating gofer": "gofer_creation",
    "mount": "mount",
    "unshare": "unshare",
    "namespace": "namespace",
    "seccomp": "seccomp",
    "apparmor": "apparmor",
    "systrap": "systrap",
    "timed out": "timeout",
    "modulenotfounderror": "python_module_missing",
    "assertionerror": "assertion_failed",
}


def stderr_summary(text):
    """A vocabulary summary, not regex-redacted arbitrary stderr/credentials."""
    observed = text.lower()
    codes = sorted({code for phrase, code in PHRASES.items() if phrase in observed})
    numbers = {int(value) for value in re.findall(r"\berrno[\s:=\[]+(\d{1,3})\b", observed)}
    inferred = {name for phrase, name in (("operation not permitted", "EPERM"), ("permission denied", "EACCES"),
                ("read-only file system", "EROFS"), ("invalid argument", "EINVAL"),
                ("no such file or directory", "ENOENT")) if phrase in observed}
    return {"categories": codes, "errno_names": sorted({errno.errorcode[n] for n in numbers if n in errno.errorcode}),
            "inferred_errno_names": sorted(inferred),
            "text_omitted": True, "truncated": len(text) > 8192}


def identifier(value):
    return value if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.<>]{0,240}", value) else "<redacted>"


def exception_info(exc):
    number = exc.errno if isinstance(exc, OSError) else None
    return {"exception_type": identifier(type(exc).__name__), "errno": number,
            "errno_name": errno.errorcode.get(number), "stderr_summary": stderr_summary(str(exc))}


def failure_detail(test, err, project, *, subtest=False):
    """Traceback without source text, locals, exception values or subtest params."""
    kind, exc, tb = err
    frames, assertion, assertion_source = [], None, None
    project = Path(project).resolve()
    while tb:
        code = tb.tb_frame.f_code
        path = Path(code.co_filename)
        try:
            relative = path.resolve().relative_to(project)
            # Copied installations and evidence are private even below PROJECT.
            public = relative.parts[0] in {"tests", "scripts", "release", "harness", "benchmark", "evaluation", "deployment"}
        except ValueError:
            public = False
        if public:
            frames.append({"file": relative.as_posix(), "line": tb.tb_lineno,
                           "function": identifier(code.co_name)})
            if relative.parts[0] == "tests" or path.name.startswith("test_"):
                try:
                    tree = ast.parse(path.read_text())
                    candidates = [node for node in ast.walk(tree)
                                  if isinstance(node, (ast.Call, ast.Assert))
                                  and node.lineno <= tb.tb_lineno <= node.end_lineno
                                  and (isinstance(node, ast.Assert) or
                                       isinstance(node.func, ast.Attribute) and node.func.attr.startswith("assert"))]
                    if candidates:
                        node = min(candidates, key=lambda n: n.end_lineno - n.lineno)
                        assertion = "assert" if isinstance(node, ast.Assert) else identifier(node.func.attr)
                        class HideLiterals(ast.NodeTransformer):
                            def visit_Constant(self, value):
                                if isinstance(value.value, (str, bytes)):
                                    return ast.copy_location(ast.Constant("<redacted>"), value)
                                return value
                        assertion_source = ast.unparse(HideLiterals().visit(node))[:500]
                except (OSError, SyntaxError, UnicodeError):
                    pass
        tb = tb.tb_next
    return {"test": identifier(test.id()), "subtest": subtest,
            **exception_info(exc), "assertion_kind": assertion if issubclass(kind, AssertionError) else None,
            "assertion_source": assertion_source if issubclass(kind, AssertionError) else None,
            "traceback": frames[-12:], "exception_message_omitted": True}


def path_status(path, *, probe=False):
    """Inspect named paths without publishing their potentially private values."""
    try:
        path = Path(path)
        info = path.stat()
        result = {"exists": True, "uid": info.st_uid, "gid": info.st_gid,
                  "mode": oct(info.st_mode & 0o7777), "directory": path.is_dir(), "symlink": path.is_symlink()}
        if probe:
            import tempfile
            with tempfile.TemporaryFile(dir=path) as stream:
                stream.write(b"fixture")
                stream.flush()
            result["write_probe"] = "PASS"
        return result
    except OSError as exc:
        return {"exists": False if isinstance(exc, FileNotFoundError) else None, **exception_info(exc),
                "write_probe": "FAIL" if probe else None}
