#!/usr/bin/env bash
# Installs official upstream packages in the environment that executes the CLI.
set -euo pipefail
release_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$release_root"
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  printf '%s\n' 'This verified codec/runtime lock supports Linux x86_64 only.' >&2
  exit 1
fi
mkdir -p .tools .tools/_install-cache/config
# npm rejects loading the same physical file as both user and global config.
: > .tools/_install-cache/config/npm-user.conf
: > .tools/_install-cache/config/npm-global.conf
export npm_config_userconfig="$release_root/.tools/_install-cache/config/npm-user.conf"
export npm_config_globalconfig="$release_root/.tools/_install-cache/config/npm-global.conf"
export npm_config_update_notifier=false npm_config_audit=false npm_config_fund=false
export npm_config_cache="${CAMACT_INSTALL_CACHE:-$release_root/.tools/_install-cache/npm}"
python3 - "$release_root" <<'PY'
import hashlib,json,os,subprocess,sys,tarfile,tempfile,urllib.request
from pathlib import Path
root=Path(sys.argv[1]); lock=json.loads((root/'locks/runtimes.json').read_text())
for name in ('node','gvisor'):
    entry=lock[name]; target=root/'.tools'/('node' if name=='node' else 'gvisor/'+entry['version'])
    binary=target/('bin/node' if name=='node' else 'runsc')
    if binary.exists():
        actual=subprocess.check_output([str(binary),'--version'],text=True)
        if entry['version'] not in actual: raise SystemExit(f'{name}: installed version differs')
        continue
    archive=root/'.tools/_install-cache'/entry['url'].rsplit('/',1)[-1]
    algorithm='sha256' if 'sha256' in entry else 'sha512'
    expected=entry[algorithm]
    def verified():
        return archive.is_file() and hashlib.new(algorithm,archive.read_bytes()).hexdigest()==expected
    if not verified():
        partial=archive.with_suffix(archive.suffix+'.partial')
        with urllib.request.urlopen(entry['url'],timeout=180) as response,partial.open('wb') as output:
            while block:=response.read(1024*1024): output.write(block)
        partial.replace(archive)
    if not verified(): raise SystemExit(f'{name}: archive digest mismatch')
    target.mkdir(parents=True,exist_ok=True)
    # The archives are authenticated by the pinned digest before extraction.
    with tarfile.open(archive) as package:
        if name=='node':
            subprocess.run(['tar','-xJf',str(archive),'--strip-components=1','-C',str(target)],check=True)
        else:
            package.extractall(target,filter='data')
    if not binary.is_file(): raise SystemExit(f'{name}: executable missing after extraction')
    if name=='gvisor':
        for path in target.rglob('*'):
            if path.is_file(): path.chmod(path.stat().st_mode | 0o555)
PY
export PATH="$release_root/.tools/node/bin:/usr/local/bin:/usr/bin:/bin"
for runtime_name in claude codex opencode deepseek openclaw; do
  mkdir -p ".tools/$runtime_name"
  cp "locks/cli/$runtime_name/package.json" "locks/cli/$runtime_name/package-lock.json" ".tools/$runtime_name/"
  "$release_root/.tools/node/bin/npm" ci --prefix ".tools/$runtime_name" --no-audit --no-fund
done
python3 scripts/check-runtimes.py --skip-codecs
