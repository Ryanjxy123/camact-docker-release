# SPDX-License-Identifier: Apache-2.0
# Research only; never loaded by install-host.sh or production Compose.
# Derived from Moby's docker-default template (Apache-2.0), retaining proc/sys,
# network, signal and ptrace confinement. Only scoped mount/pivot permissions
# replace the blanket deny mount; no outer container capability is added.
# Sources: moby/profiles/apparmor/template.go; google/gvisor tag
# release-20261012.0 runsc/cmd/sandboxsetup/gofer_mount.go and
# runsc/cmd/sentry/sentrycmd/chroot.go.
abi <abi/4.0>,
#include <tunables/global>
profile camact-gvisor-diagnostic-v1 flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  network,
  network unix,
  deny network raw,
  capability,
  file,
  userns,
  umount,
  signal (receive) peer=unconfined,
  signal (receive) peer=runc,
  signal (receive) peer=crun,
  signal (send,receive) peer=camact-gvisor-diagnostic-v1,
  ptrace (trace,tracedby,read,readby) peer=camact-gvisor-diagnostic-v1,

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
  mount fstype=tmpfs options=(rw,nosuid,nodev) -> /tmp/camact-diag-*/ns-*/target/,
  mount options=(rw,rbind) /tmp/camact-diag-*/ns-*/source/ -> /tmp/camact-diag-*/ns-*/target/,
  mount options=(ro,remount,bind,nosuid,nodev) -> /tmp/camact-diag-*/ns-*/target/,
  mount options=(ro,remount,bind,nosuid,nodev,noexec) -> /tmp/camact-diag-*/ns-*/target/,
  mount options=(ro,remount,bind,nosuid,nodev,relatime) -> /tmp/camact-diag-*/ns-*/target/,
  mount options=(ro,remount,bind,nosuid,nodev,noexec,relatime) -> /tmp/camact-diag-*/ns-*/target/,
  mount options=(ro,remount,bind,nosuid,nodev,strictatime) -> /tmp/camact-diag-*/ns-*/target/,
  mount options=(ro,remount,bind,nosuid,nodev,noexec,strictatime) -> /tmp/camact-diag-*/ns-*/target/,

  # Gofer staging tree used by the locked runtime, inside a fresh user/mount ns.
  mount fstype=tmpfs options=(rw,nosuid,nodev,noexec) -> /proc/fs/,
  mount options=(rw,unbindable) -> /proc/fs/,
  mount options=(ro,rbind,nosuid,nodev,noexec) /proc/ -> /proc/fs/proc/,
  mount options=(ro,bind,nosuid,nodev,noexec) /proc/fs/proc/*/fd/ -> /proc/fs/proc/fs/,
  mount options=(rw,rbind) /var/lib/camact/scratch/gvisor/gvisor-*/rootfs/ -> /proc/fs/root/,
  mount options=(rw,rslave) -> /proc/fs/root/,
  mount options=(ro,remount,bind,nosuid,nodev) -> /proc/fs/root/,
  mount options=(ro,rbind,nosuid,nodev) /{usr,usr/bin,usr/sbin,usr/lib,usr/lib64,bin,sbin,lib,lib64}/ -> /proc/fs/root/{usr,bin,sbin,lib,lib64}/,
  mount options=(ro,remount,rbind,nosuid,nodev,relatime) -> /proc/fs/root/{usr,bin,sbin,lib,lib64}/,
  mount options=(ro,remount,rbind,nosuid,nodev,strictatime) -> /proc/fs/root/{usr,bin,sbin,lib,lib64}/,
  pivot_root /proc/fs/,

  # Sentry's own private chroot; actual denied flags/paths drive any changes.
  mount fstype=tmpfs options=(rw,nosuid,nodev,noexec) -> /var/lib/camact/scratch/gvisor/gvisor-*/tmp/,
  mount fstype=tmpfs options=(rw,nosuid,nodev,noexec) -> /var/lib/camact/scratch/gvisor/gvisor-*/tmp/proc/,
  mount fstype=proc options=(ro,nosuid,nodev,noexec) -> /var/lib/camact/scratch/gvisor/gvisor-*/tmp/proc/sandbox-proc/,
  mount options=(ro,rbind,nosuid,nodev,noexec) /proc/ -> /var/lib/camact/scratch/gvisor/gvisor-*/tmp/proc/host-proc/,
  mount options=(ro,remount,bind) -> /var/lib/camact/scratch/gvisor/gvisor-*/tmp/,
  pivot_root /var/lib/camact/scratch/gvisor/gvisor-*/tmp/,
}
