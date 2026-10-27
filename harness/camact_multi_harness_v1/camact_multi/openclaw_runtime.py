"""OpenClaw-only POSIX HOME and passive native-session collection.

No OpenClaw code, security check, compaction setting or tool is replaced.
The Windows archive is a copy, never the live private state directory.
"""
from __future__ import annotations
import hashlib
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
from claude_code_harness.core import write_json
from .transport import redact

PRIVATE_DIRS = ('', '.openclaw', '.openclaw/agents', '.openclaw/agents/main',
                '.openclaw/agents/main/agent', '.openclaw/agents/main/sessions')

def session_final_text(events):
    for row in reversed(events):
        event=row.get('native_event',{})
        message=event.get('message',{})
        if event.get('type')=='message' and message.get('role')=='assistant' and message.get('stopReason')=='stop':
            return '\n'.join(b.get('text','') for b in message.get('content',[]) if b.get('type')=='text')
    return ''

class OpenClawHome:
    def __init__(self, output: Path, secrets=(), *, backend='ext4', max_tmpfs_bytes=268435456):
        self.output, self.secrets = output, tuple(s for s in secrets if s)
        if backend not in {'ext4', 'tmpfs'}:
            raise ValueError('Unsupported OpenClaw HOME backend')
        self.backend, self.max_tmpfs_bytes = backend, max_tmpfs_bytes
        self.offsets, self.events, self.errors = {}, [], []
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.archive_ok = False

    def __enter__(self):
        supplied = Path(os.environ.get('CAMACT_OPENCLAW_TMPDIR', '/tmp'))
        if supplied.is_symlink():
            raise RuntimeError('OpenClaw HOME parent must not be a symlink')
        self.temp_parent = supplied.resolve(strict=True)
        filesystem = self._check_filesystem(self.temp_parent)
        self.root = Path(tempfile.mkdtemp(prefix='camact-openclaw-', dir=self.temp_parent)).resolve()
        self.home = self.root / 'home'
        for relative in PRIVATE_DIRS:
            p = self.home / relative
            p.mkdir(parents=True, exist_ok=True, mode=0o700)
            p.chmod(0o700)
            if p.stat().st_uid != os.geteuid() or p.stat().st_mode & 0o777 != 0o700:
                raise RuntimeError(f'OpenClaw private directory is not owned 0700: {p}')
        filesystem = self._check_filesystem(self.home)
        self.lease = os.open(self.root/'.camact-home.lock', os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW, 0o600)
        fcntl.flock(self.lease, fcntl.LOCK_EX|fcntl.LOCK_NB)
        write_json(self.output/'openclaw-runtime-location.json', {
            'live_home': str(self.home), 'sandbox_home':'/home/agent', 'filesystem':filesystem,
            'uid':os.geteuid(), 'archive_home':str(self.output/'home'),
            'live_archive_same_filesystem':self.home.stat().st_dev==self.output.stat().st_dev,
            'private_directory_mode':'0700', 'child_umask':'0077',
            'storage_backend':self.backend,
            'official_security_and_compaction_unchanged':True})
        self.thread = threading.Thread(target=self._poll,daemon=True)
        self.thread.start()
        return self

    def _check_filesystem(self, path):
        filesystem = subprocess.check_output(['stat','-f','-c','%T',str(path)],text=True).strip()
        if self.backend == 'ext4':
            if filesystem not in {'ext2/ext3', 'ext4'}:
                raise RuntimeError(f'OpenClaw live HOME requires ext4, got {filesystem}')
        else:
            st = self.temp_parent.stat()
            if filesystem != 'tmpfs' or st.st_uid != os.geteuid() or st.st_mode & 0o777 != 0o700:
                raise RuntimeError('OpenClaw tmpfs HOME requires a real, owned 0700 tmpfs')
            capacity = os.statvfs(path).f_blocks * os.statvfs(path).f_frsize
            if not 0 < capacity <= self.max_tmpfs_bytes:
                raise RuntimeError('OpenClaw tmpfs capacity exceeds its explicit limit')
            mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
            parent_mount = next((m for m in mounts if m[4] == str(self.temp_parent)), None)
            if parent_mount is None or any(v.startswith(('shared:', 'master:')) for v in parent_mount[6:parent_mount.index('-')]):
                raise RuntimeError('OpenClaw tmpfs must be an explicit private mount')
        return filesystem

    def _poll(self):
        while not self.stop.wait(.25):
            try: self.collect()
            except Exception as exc: self.errors.append(f'{type(exc).__name__}: {exc}')

    def collect(self):
        with self.lock:
            for p in sorted((self.home/'.openclaw/agents').glob('*/sessions/*.jsonl')):
                if any(part.is_symlink() for part in (p, *p.parents) if part.is_relative_to(self.home)):
                    raise RuntimeError('OpenClaw session path must not contain symlinks')
                relative = str(p.relative_to(self.home))
                stat = p.stat()
                prior = self.offsets.get(relative, {'offset':0,'inode':stat.st_ino,'version':0})
                if prior['inode'] != stat.st_ino or prior['offset'] > stat.st_size:
                    prior = {'offset':0,'inode':stat.st_ino,'version':prior['version']+1}
                with p.open('rb') as src:
                    src.seek(prior['offset'])
                    while True:
                        offset=src.tell(); line=src.readline()
                        if not line or not line.endswith(b'\n'): break
                        text=redact(line.decode('utf-8'),self.secrets)
                        try: native=json.loads(text)
                        except ValueError:
                            self.errors.append(f'Invalid native JSONL: {relative}:{offset}')
                            prior['offset']=src.tell();continue
                        row={'type':'openclaw.native_session_event','source_file':relative,
                             'source_offset_bytes':offset,'source_version':prior['version'],
                             'captured_at':time.time(),'native_event':native}
                        with (self.output/'native-session-events.jsonl').open('a',encoding='utf-8') as dst:
                            dst.write(json.dumps(row,ensure_ascii=False)+'\n')
                            dst.flush()
                        self.events.append(row);prior['offset']=src.tell()
                self.offsets[relative]=prior

    def archive(self):
        self.stop.set();self.thread.join(10);self.collect()
        entries=[]
        for p in sorted([self.home,*self.home.rglob('*')]):
            st=p.lstat();row={'path':str(p.relative_to(self.home)), 'mode':oct(st.st_mode&0o7777),
                             'uid':st.st_uid,'gid':st.st_gid,'symlink':p.is_symlink()}
            # Official plugin-skills links refer to the read-only guest
            # runtime. Preserve the link itself; never follow it on the host.
            if p.is_symlink():
                row['link_target'] = os.readlink(p)
            if not p.is_symlink() and p.is_file():
                data=p.read_bytes()
                if any(s.encode() in data for s in self.secrets):
                    raise RuntimeError(f'Credential detected in private HOME; retained private source: {p}')
                row.update(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
            entries.append(row)
        shutil.copytree(self.home,self.output/'home',symlinks=True)
        for row in entries:
            if 'sha256' in row:
                target=self.output/'home'/row['path']
                if hashlib.sha256(target.read_bytes()).hexdigest()!=row['sha256']:
                    raise RuntimeError(f'OpenClaw archive mismatch: {row["path"]}')
        archive_name = f'home.{self.backend}.tar.gz'
        with tarfile.open(self.output/archive_name,'w:gz',dereference=False) as out:
            out.add(self.home,arcname='home',recursive=True)
        write_json(self.output/'home-posix-manifest.json',{'live_home':str(self.home),
                   'entries':entries,'archived_bytes_verified':True,
                   'storage_backend':self.backend, 'posix_archive':archive_name,
                   'mode_preservation':'source metadata and POSIX tar; copied modes are not authoritative'})
        write_json(self.output/'native-session-capture.json',{'events':len(self.events),'sources':self.offsets,
                   'errors':self.errors,'independent_of_final_stdout':True,'incremental_flush':True})
        self.archive_ok=True

    def __exit__(self,*_):
        try:
            self.archive()
        finally:
            self.stop.set();self.thread.join(10)
            os.close(self.lease)
            # Retain ext4 evidence if copying/verification fails. Only remove the
            # exact mkdtemp directory after a verified archive, never a derived path.
            if self.archive_ok:
                if self.root.parent!=self.temp_parent or not self.root.name.startswith('camact-openclaw-') or self.root.is_symlink():
                    raise RuntimeError('Unsafe OpenClaw temporary HOME cleanup path')
                shutil.rmtree(self.root)

def sandbox_preflight(command_builder, workspace, storage, entry, output):
    code = """import json,os,pathlib
paths=['/home/agent','/home/agent/.openclaw','/home/agent/.openclaw/agents/main/agent','/home/agent/.openclaw/agents/main/sessions']
rows=[]
for p in paths:
 s=os.stat(p);mode=s.st_mode&0o777
 assert mode==0o700 and s.st_uid==os.geteuid(),(p,mode,s.st_uid,os.geteuid())
 rows.append({'path':p,'mode':oct(mode),'uid':s.st_uid,'gid':s.st_gid,'device':s.st_dev})
probe=pathlib.Path(paths[2])/'posix-mode-probe'
fd=os.open(probe,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
assert probe.stat().st_mode&0o777==0o600
probe.unlink()
print(json.dumps({'euid':os.geteuid(),'egid':os.getegid(),'paths':rows,'file_mode_0600_verified':True,'mounts':[l for l in pathlib.Path('/proc/self/mountinfo').read_text().splitlines() if ' /home/agent ' in l or ' /tmp ' in l]}))
"""
    cmd=command_builder(['/usr/bin/python3','-c',code],workspace,storage.home,entry,relay=False)
    r=subprocess.run(cmd,capture_output=True,text=True,timeout=30,umask=0o077,
                     env={'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
                          'PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1'})
    write_json(output/'sandbox-permissions.json',{'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr,
                                               'proof':json.loads(r.stdout) if r.returncode==0 else None})
    if r.returncode: raise RuntimeError('OpenClaw sandbox POSIX permission preflight failed')
