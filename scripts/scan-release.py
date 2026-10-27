#!/usr/bin/env python3
"""Scan publishable files; report locations/counts, never candidate secret text."""
from pathlib import Path
import argparse
import fnmatch
import ipaddress
import json
import os
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {'.git', '.validation', '.tools', '.data', '.secrets', '.state', '__pycache__', 'node_modules', 'target'}
ENV_TEMPLATES = {'.env.example', 'config/models.env.example'}
PERSONAL_CONFIG_NAMES = {'.ssh', '.aws', '.npmrc', '.netrc', '.pypirc', 'id_rsa'}
SECRET_PATTERNS = {
    'provider_key': re.compile(r'\b(?:sk-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b'),
    'private_key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'url_credentials': re.compile(r'https?://[^\s/\x22\x27]+:[^\s/\x22\x27]+@'),
    'personal_project_path': re.compile(r'/home/(?:dataset-assist|batchcom)|[A-Z]:\\(?:projects|Users)\\'),
    'personal_home_path': re.compile(r'/home/(?!(?:agent|fixture)(?:[/_.-]|\b))[A-Za-z0-9_.-]+'),
    'personal_mount_path': re.compile(r'/mnt/[a-z]/(?:projects?|Users)/[A-Za-z0-9_.-]+'),
}


def personal_config_path(relative):
    """Reject credential containers before reading potentially opaque contents."""
    if relative.as_posix() in ENV_TEMPLATES:
        return False
    return (any(part in PERSONAL_CONFIG_NAMES
                or any(fnmatch.fnmatchcase(part, pattern) for pattern in ('.env*', '*.pem', '*.key'))
                for part in relative.parts)
            or (len(relative.parts) == 2 and relative.parts[0] == 'config'
                and fnmatch.fnmatchcase(relative.name, '*.env*')))


def candidates(tracked):
    if tracked:
        result = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT, capture_output=True, check=True)
        return [ROOT / value.decode() for value in result.stdout.split(b'\0') if value]
    paths = []
    for directory, dirs, names in os.walk(ROOT):
        dirs[:] = [name for name in dirs if name not in EXCLUDED]
        paths.extend(Path(directory) / name for name in dirs if (Path(directory) / name).is_symlink())
        for name in names:
            p = Path(directory) / name
            if str(p.relative_to(ROOT)) not in {'.env', 'config/models.env'}:
                paths.append(p)
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tracked', action='store_true')
    args = parser.parse_args()
    issues = []
    files = candidates(args.tracked)
    for path in files:
        relative = path.relative_to(ROOT)
        rel = relative.as_posix()
        if set(relative.parts) & EXCLUDED or rel in {'.env', 'config/models.env'}:
            issues.append({'file': rel, 'kind': 'forbidden_tracked_path'})
            continue
        if personal_config_path(relative):
            issues.append({'file': rel, 'kind': 'personal_config_or_credential_path'})
            continue
        if path.is_symlink():
            issues.append({'file': rel, 'kind': 'publishable_symlink'})
            continue
        content = path.read_bytes()
        if b'\0' in content:
            issues.append({'file': rel, 'kind': 'unexpected_binary'})
            continue
        text = content.decode('utf-8', errors='replace')
        for name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                issues.append({'file': rel, 'line': text.count('\n', 0, match.start()) + 1, 'kind': name})
        for match in re.finditer(r'https?://(\d+\.\d+\.\d+\.\d+)(?::\d+)?', text):
            address = ipaddress.ip_address(match.group(1))
            if not address.is_loopback and not address.is_unspecified:
                issues.append({'file': rel, 'line': text.count('\n', 0, match.start()) + 1, 'kind': 'numeric_gateway'})
        if (rel.startswith(('benchmark/tasks/', 'benchmark/users/')) or path.suffix in {'.log', '.jsonl'}
                or path.name in {'result.json', 'run_manifest.json', 'formal_config.json', 'auth.json', '.npmrc'}):
            issues.append({'file': rel, 'kind': 'data_or_runtime_artifact'})
    print(json.dumps({'files_scanned': len(files), 'issues': issues, 'issue_count': len(issues),
                      'scope': 'tracked-files' if args.tracked else 'publishable-source',
                      'note': 'Pattern scan is evidence, not a proof against unknown secret formats.'}, ensure_ascii=False, indent=2))
    return bool(issues)


if __name__ == '__main__':
    sys.exit(main())
