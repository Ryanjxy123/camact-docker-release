#!/usr/bin/env python3
"""Trusted, networkless one-shot storage ownership and external secret injection."""
import os
from pathlib import Path
import sys

os.umask(0o077)
for root in (Path('/var/lib/camact'), Path('/secrets')):
    if root.is_symlink():
        raise SystemExit('Storage root must not be a symbolic link')
    root.mkdir(parents=True, exist_ok=True)
    os.chown(root, 10001, 10001)
    # Compose may stat a known secret source as the unprivileged host client;
    # only the container UID can read its 0400 contents or list this directory.
    root.chmod(0o711 if root == Path('/secrets') else 0o700)
for name in ('benchmark', 'results', 'logs', 'cache', 'scratch', 'checkpoints'):
    path = Path('/var/lib/camact') / name
    if path.is_symlink():
        raise SystemExit('Persistent directory must not be a symbolic link')
    path.mkdir(exist_ok=True)
    os.chown(path, 10001, 10001)
    path.chmod(0o700)
for role in ('agent', 'judge', 'simulator'):
    path = Path('/secrets') / (role + '_api_key')
    fd = os.open(path, os.O_CREAT | os.O_NOFOLLOW | os.O_WRONLY, 0o400)
    try:
        os.fchown(fd, 10001, 10001)
        os.fchmod(fd, 0o400)
    finally:
        os.close(fd)
if len(sys.argv) > 1:
    if len(sys.argv) != 3 or sys.argv[1] != 'secret' or sys.argv[2] not in ('agent', 'judge', 'simulator'):
        raise SystemExit('Expected: secret agent|judge|simulator')
    value = sys.stdin.buffer.read(16385)
    if not value or len(value) > 16384 or b'\n' in value or b'\r' in value or b'\0' in value:
        raise SystemExit('Secret must be one nonempty line, at most 16 KiB')
    path = Path('/secrets') / (sys.argv[2] + '_api_key')
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        raise SystemExit('Secret write failed')
print('Storage initialized; external secret values are never printed.')
