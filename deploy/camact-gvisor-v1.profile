# SPDX-License-Identifier: Apache-2.0
# Bounded rootless Systrap policy; production acceptance remains mandatory.
# Derived from Moby docker-default and the release-20261012.0 Gofer/Sentry
# mount sequence. Retains the original proc/sys, network, signal and ptrace
# restrictions. The outer runner still has no capabilities.
abi <abi/4.0>,
#include <tunables/global>

# Only these six literal macro lines may be rendered by the scoped installer.
@{CAMACT_RESULTS_ROOT}=/var/lib/camact/results
@{CAMACT_CACHE_ROOT}=/var/lib/camact/benchmark
@{CAMACT_SCRATCH_ROOT}=/var/lib/camact/scratch
@{CAMACT_GVISOR_STATE_ROOT}=/var/lib/camact/scratch/gvisor
@{CAMACT_CACHE_REPOSITORY}=Ryanjxy--CamAct-Benchmark-7574a0301bfc
@{CAMACT_BENCHMARK_REVISION}=53e2f450042485dfc4a3b566de6f46988c3a5661

@{CAMACT_NAMESPACE_ROOT}=/tmp/camact-namespace-diagnostics-*
@{CAMACT_GVISOR_PREFLIGHT_ROOT}=@{CAMACT_SCRATCH_ROOT}/camact-gvisor-diagnostic-*
@{CAMACT_VERSION_FIXTURE}=@{CAMACT_SCRATCH_ROOT}/camact-sandbox-check-*/{claude,codex,opencode,deepseek,openclaw,credential-boundary}
@{CAMACT_NATIVE_CASE}=@{CAMACT_SCRATCH_ROOT}/docker-gates-*/{claude,codex,opencode,deepseek,openclaw}-{single_turn,multi_turn,users_history}
@{CAMACT_SHARED_NATIVE_CASE}=@{CAMACT_SCRATCH_ROOT}/docker-gates-*/{codex,opencode,deepseek,openclaw}-{single_turn,multi_turn,users_history}
@{CAMACT_CLAUDE_NATIVE_CASE}=@{CAMACT_SCRATCH_ROOT}/docker-gates-*/claude-{single_turn,multi_turn,users_history}
@{CAMACT_FORMAL_SHARED_EXECUTION}=@{CAMACT_RESULTS_ROOT}/*/users/*/runs/{codex,opencode,deepseek,openclaw}/task_*/attempt_[0-9][0-9][0-9]/run/runs/execution
@{CAMACT_FORMAL_ORDINARY_EXECUTION}=@{CAMACT_RESULTS_ROOT}/*/users/*/runs/{codex,opencode,deepseek}/task_*/attempt_[0-9][0-9][0-9]/run/runs/execution
@{CAMACT_FORMAL_CLAUDE_EXECUTION}=@{CAMACT_RESULTS_ROOT}/*/users/*/runs/claude/task_*/attempt_[0-9][0-9][0-9]/run/runs/execution
@{CAMACT_NATIVE_WORKSPACE}=@{CAMACT_SHARED_NATIVE_CASE}/run/runs/execution/workspace @{CAMACT_CLAUDE_NATIVE_CASE}/run/runs/execution/tasks/fixture_user/task_fixture/workspace
@{CAMACT_FORMAL_WORKSPACE}=@{CAMACT_FORMAL_SHARED_EXECUTION}/workspace @{CAMACT_FORMAL_CLAUDE_EXECUTION}/tasks/*/task_*/workspace
@{CAMACT_WORKSPACE}=@{CAMACT_GVISOR_PREFLIGHT_ROOT}/workspace @{CAMACT_VERSION_FIXTURE}/workspace @{CAMACT_NATIVE_WORKSPACE} @{CAMACT_FORMAL_WORKSPACE}
@{CAMACT_ORDINARY_HOME}=@{CAMACT_GVISOR_PREFLIGHT_ROOT}/home @{CAMACT_VERSION_FIXTURE}/home @{CAMACT_SCRATCH_ROOT}/docker-gates-*/{codex,opencode,deepseek}-{single_turn,multi_turn,users_history}/run/runs/execution/home @{CAMACT_FORMAL_ORDINARY_EXECUTION}/home
@{CAMACT_CLAUDE_HOME}=@{CAMACT_CLAUDE_NATIVE_CASE}/run/runs/execution/tasks/fixture_user/task_fixture/claude_config/attempt_[0-9][0-9] @{CAMACT_FORMAL_CLAUDE_EXECUTION}/tasks/*/task_*/claude_config/attempt_[0-9][0-9]
@{CAMACT_STATE}=@{CAMACT_GVISOR_STATE_ROOT}/run-* @{CAMACT_SCRATCH_ROOT}/camact-sandbox-check-*/gvisor-state/run-* @{CAMACT_SCRATCH_ROOT}/docker-gates-*/gvisor-state/run-* @{CAMACT_GVISOR_PREFLIGHT_ROOT}/runtime/run-*
@{CAMACT_MEMORY_TARGET}=@{CAMACT_CACHE_ROOT}/@{CAMACT_CACHE_REPOSITORY}/@{CAMACT_BENCHMARK_REVISION}/snapshot/users/*/base_memory

profile camact-gvisor-v1 flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  network,
  network unix,
  deny network raw,
  deny network ax25,
  deny network ipx,
  deny network appletalk,
  deny network netrom,
  deny network rose,
  deny network econet,
  deny network atmsvc,
  deny network irda,
  deny network wanpipe,
  deny network isdn,
  deny network caif,
  deny network alg,
  deny network vsock,
  capability,
  file,
  userns,
  umount,
  signal (receive) peer=unconfined,
  signal (receive) peer=runc,
  signal (receive) peer=crun,
  signal (send,receive) peer=camact-gvisor-v1,
  ptrace (trace,tracedby,read,readby) peer=camact-gvisor-v1,

  audit deny @{PROC}/* w,
  # The Moby two-character directory pattern excludes exactly fs, the pinned
  # runsc staging tmpfs. All other original proc/sys denies are retained.
  audit deny @{PROC}/{[^1-9/],[^1-9f/][^0-9/],f[^s0-9/],[^1-9s/][^0-9y/][^0-9s/],[^1-9/][^0-9/][^0-9/][^0-9/]*}/** w,
  audit deny @{PROC}/sys/[^k]** w,
  audit deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/kcore rwklx,
  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/** rwklx,
  deny /sys/devices/virtual/powercap/** rwklx,
  deny /sys/kernel/security/** rwklx,

  # Unlisted mount operations remain implicitly denied and audited.
  # No shared propagation, disk filesystems, host paths or global sysctl edits.
  mount options=(rw,rprivate) -> /,
  mount options=(rw,rslave) -> /,
  mount fstype=tmpfs options=(rw,nosuid,nodev) -> @{CAMACT_NAMESPACE_ROOT}/ns-*/target/,
  mount options=(rw,rbind) @{CAMACT_NAMESPACE_ROOT}/ns-*/source/ -> @{CAMACT_NAMESPACE_ROOT}/ns-*/target/,
  mount options=(ro,remount,bind,nosuid,nodev) -> @{CAMACT_NAMESPACE_ROOT}/ns-*/target/,
  mount options=(ro,remount,bind,nosuid,nodev,noexec) -> @{CAMACT_NAMESPACE_ROOT}/ns-*/target/,
  mount options=(ro,remount,bind,nosuid,nodev,relatime) -> @{CAMACT_NAMESPACE_ROOT}/ns-*/target/,
  mount options=(ro,remount,bind,nosuid,nodev,noexec,relatime) -> @{CAMACT_NAMESPACE_ROOT}/ns-*/target/,
  mount options=(ro,remount,bind,nosuid,nodev,strictatime) -> @{CAMACT_NAMESPACE_ROOT}/ns-*/target/,
  mount options=(ro,remount,bind,nosuid,nodev,noexec,strictatime) -> @{CAMACT_NAMESPACE_ROOT}/ns-*/target/,

  # Gofer staging tree used by the locked runtime, inside a fresh user/mount ns.
  mount fstype=tmpfs options=(rw,nosuid,nodev,noexec) -> /proc/fs/,
  mount options=(rw,unbindable) -> /proc/fs/,
  mount options=(ro,rbind,nosuid,nodev,noexec) /proc/ -> /proc/fs/proc/,
  mount options=(ro,bind,nosuid,nodev,noexec) /proc/fs/proc/*/fd/ -> /proc/fs/proc/fs/,
  mount options=(rw,rslave) -> /proc/fs/root/,
  mount options=(ro,remount,bind,nosuid,nodev) -> /proc/fs/root/,
  mount options=(ro,rbind,nosuid,nodev) /{usr,usr/bin,usr/sbin,usr/lib,usr/lib64,bin,sbin,lib,lib64}/ -> /proc/fs/root/{usr,bin,sbin,lib,lib64}/,
  mount options=(ro,remount,rbind,nosuid,nodev,relatime) -> /proc/fs/root/{usr,bin,sbin,lib,lib64}/,
  mount options=(ro,remount,rbind,nosuid,nodev,strictatime) -> /proc/fs/root/{usr,bin,sbin,lib,lib64}/,
  pivot_root oldroot=/proc/fs/ /proc/fs/,

  # OCI run-* state only; no general scratch or results mount permission.
  mount options=(rw,rbind) @{CAMACT_STATE}/rootfs/ -> /proc/fs/root/,
  mount fstype=tmpfs options=(rw,nosuid,nodev,noexec) -> @{CAMACT_STATE}/tmp/,
  mount fstype=tmpfs options=(rw,nosuid,nodev,noexec) -> @{CAMACT_STATE}/tmp/proc/,
  mount fstype=proc options=(ro,nosuid,nodev,noexec) -> @{CAMACT_STATE}/tmp/proc/sandbox-proc/,
  mount options=(ro,rbind,nosuid,nodev,noexec) /proc/ -> @{CAMACT_STATE}/tmp/proc/host-proc/,
  mount options=(ro,remount,bind) -> @{CAMACT_STATE}/tmp/,
  pivot_root oldroot=@{CAMACT_STATE}/tmp/ @{CAMACT_STATE}/tmp/,

  mount options=(ro,rbind,nosuid,nodev) /etc/{ssl/certs/,fonts/,ld.so.cache,localtime} -> /proc/fs/root/etc/{ssl/certs/,fonts/,ld.so.cache,localtime},
  mount options=(ro,rbind,nosuid,nodev) /usr/share/zoneinfo/** -> /proc/fs/root/etc/localtime,
  mount options=(ro,rbind,nosuid,nodev) /opt/camact/.tools/{claude,codex,opencode,deepseek,openclaw,node}/ -> /proc/fs/root/opt/camact/runtime/[01]/,
  mount options=(ro,rbind,nosuid,nodev) /opt/camact/.tools/node/bin/node -> /proc/fs/root/opt/node,

  mount options=(rw,rbind,nosuid,nodev) @{CAMACT_WORKSPACE}/ -> /proc/fs/root/tmp/,
  mount options=(rw,rbind,nosuid,nodev) @{CAMACT_ORDINARY_HOME}/ -> /proc/fs/root/home/agent/,
  mount options=(rw,rbind,nosuid,nodev) @{CAMACT_CLAUDE_HOME}/ -> /proc/fs/root/home/,
  mount options=(rw,rbind,nosuid,nodev) /run/camact/openclaw/camact-openclaw-*/home/ -> /proc/fs/root/home/agent/,
  mount options=(ro,rbind,nosuid,nodev) @{CAMACT_WORKSPACE}/{album,context,.camact}/ -> /proc/fs/root/tmp/{album,context,.camact}/,

  # The source is always an isolated task album. Never bind the cache itself.
  # The unchanged prompt/alias builder supplies the current user's destination.
  mount options=(ro,rbind,nosuid,nodev) @{CAMACT_FORMAL_WORKSPACE}/album/ -> /proc/fs/root@{CAMACT_MEMORY_TARGET}/,
  mount options=(ro,rbind,nosuid,nodev) @{CAMACT_NATIVE_WORKSPACE}/album/ -> /proc/fs/root@{CAMACT_NATIVE_CASE}/synthetic-benchmark/users/fixture_user/base_memory/,
  mount options=(ro,rbind,nosuid,nodev) /tmp/camact-multi-*/ -> /proc/fs/root/transport/,
  mount options=(ro,rbind,nosuid,nodev) /tmp/camact-native-relay-*/camact-multi-*/ -> /proc/fs/root/transport/,
  mount options=(ro,rbind,nosuid,nodev) /tmp/camact-transport-*/ -> /proc/fs/root/transport/,

  mount options=(ro,remount,rbind,nosuid,nodev,relatime) -> /proc/fs/root/{etc/ssl/certs/,etc/fonts/,etc/ld.so.cache,etc/localtime,opt/camact/runtime/[01]/,opt/node,tmp/album/,tmp/context/,tmp/.camact/,transport/},
  mount options=(ro,remount,rbind,nosuid,nodev,strictatime) -> /proc/fs/root/{etc/ssl/certs/,etc/fonts/,etc/ld.so.cache,etc/localtime,opt/camact/runtime/[01]/,opt/node,tmp/album/,tmp/context/,tmp/.camact/,transport/},
  mount options=(ro,remount,rbind,nosuid,nodev,relatime) -> /proc/fs/root@{CAMACT_MEMORY_TARGET}/,
  mount options=(ro,remount,rbind,nosuid,nodev,strictatime) -> /proc/fs/root@{CAMACT_MEMORY_TARGET}/,
  mount options=(ro,remount,rbind,nosuid,nodev,relatime) -> /proc/fs/root@{CAMACT_NATIVE_CASE}/synthetic-benchmark/users/fixture_user/base_memory/,
  mount options=(ro,remount,rbind,nosuid,nodev,strictatime) -> /proc/fs/root@{CAMACT_NATIVE_CASE}/synthetic-benchmark/users/fixture_user/base_memory/,
  mount options=(ro,remount,rbind,nosuid,nodev,noexec,relatime) -> /proc/fs/root/transport/,
  mount options=(ro,remount,rbind,nosuid,nodev,noexec,strictatime) -> /proc/fs/root/transport/,
  mount options=(rw,remount,rbind,nosuid,nodev,relatime) -> /proc/fs/root/{tmp/,home/,home/agent/},
  mount options=(rw,remount,rbind,nosuid,nodev,strictatime) -> /proc/fs/root/{tmp/,home/,home/agent/},
  mount options=(rw,remount,rbind,nosuid,nodev,noexec,relatime) -> /proc/fs/root/home/agent/,
  mount options=(rw,remount,rbind,nosuid,nodev,noexec,strictatime) -> /proc/fs/root/home/agent/,
}
