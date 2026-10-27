"""Shared bubblewrap boundary, reusing the existing Unix adapter protocol."""
from pathlib import Path
import shutil
from harness.camact_prompt_parity_v1.sandbox import memory_alias_mounts

def command(argv, workspace, home, entry, transport=None, *, relay=True):
    backend = entry.get('sandbox_backend', 'bwrap')
    if backend == 'gvisor':
        from .gvisor import command as gvisor_command
        return gvisor_command(argv, workspace, home, entry, transport, relay=relay)
    if backend != 'bwrap':
        raise ValueError(f'Unsupported sandbox backend: {backend}')
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise RuntimeError("bubblewrap is required")
    mounts = []
    for item in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/ssl/certs", "/etc/fonts", "/etc/ld.so.cache", "/etc/localtime"):
        if Path(item).exists():
            mounts += ["--ro-bind", item, item]
    # Mount exact Linux package roots, never an entire host HOME or Windows mount.
    for root in entry["runtime_roots"]:
        path = Path(root).resolve(strict=True)
        if (path in {Path("/"), Path("/home"), Path("/root"), Path("/mnt"), Path.home()}
                or path.parent == Path("/home") or path.as_posix().startswith("/mnt/")):
            raise ValueError("Unsafe runtime root")
        mounts += ["--ro-bind", str(path), str(path)]
        for hidden in (".env", ".npmrc", ".git"):
            target = path / hidden
            if target.is_file():
                mounts += ["--ro-bind", "/dev/null", str(target)]
            elif target.is_dir():
                mounts += ["--tmpfs", str(target)]
    if entry.get("node_executable"):
        node = Path(entry["node_executable"]).resolve(strict=True)
        if not any(node.is_relative_to(Path(root).resolve(strict=True)) for root in entry["runtime_roots"]):
            raise ValueError("Node must be inside an explicit read-only runtime root")
        mounts += ["--ro-bind", str(node), "/opt/node"]
    executable = Path(argv[0]).resolve(strict=True)
    inner = [str(executable), *argv[1:]]
    if transport:
        mounts += ["--ro-bind", str(transport), "/transport"]
    if (workspace / "album").exists():
        mounts += ["--ro-bind", str(workspace / "album"), "/tmp/album"]
    # These mounts follow the workspace bind, so append below instead.
    album_mounts = mounts[-3:] if mounts[-1:] == ["/tmp/album"] else []
    if album_mounts:
        mounts = mounts[:-3]
    result = [bwrap, "--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net",
              "--cap-drop", "ALL", *mounts, "--tmpfs", "/run", "--dir", "/run/camact",
              "--bind", str(workspace), "/tmp", "--bind", str(home), "/home/agent",
              *album_mounts, *memory_alias_mounts(workspace)]
    for folder in ("context", ".camact"):
        if (workspace / folder).exists():
            result += ["--ro-bind", str(workspace / folder), "/tmp/" + folder]
    result += ["--proc", "/proc", "--dev", "/dev", "--chdir", "/tmp"]
    if relay:
        inner = ["/usr/bin/python3", "/tmp/.camact/multi_launcher.py", *inner]
    return [*result, "--", *inner]

