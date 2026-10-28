# gVisor 环境诊断

在 GitHub Actions 选择 **Diagnose gVisor environment** → **Run workflow** →
分支 **main** → **Run workflow**。只有 `workflow_dispatch` 入口，没有发布或自动触发。
运行结果显示在日志和 Job Summary；下载 **gvisor-environment-diagnostics** Artifact，
包含 `report.json` 和 `summary.md`，保留 14 天。即使探针失败，也会尝试上传报告。

这是针对 [Run #5](https://github.com/Ryanjxy123/camact-docker-release/actions/runs/40716448471)
的轻量定位工具，不构建 CamAct，不执行 CLI、模型请求或 Benchmark，也不替代完整验收。

## 三个层级

1. **host**：以 GitHub Runner 的普通用户执行 user namespace、单 UID/GID 映射、
   user+mount namespace 和 `/bin/true`，对应旧 namespace 探针；另测试私有 mount 传播、
   tmpfs 写入/卸载、bind mount、只读 remount/写入拒绝，以及子 network namespace。
   每组运行在独立子进程，父进程和宿主挂载表不变；另原样执行 Run #5 的
   `unshare --user --map-current-user --mount true`，覆盖 util-linux 的挂载传播操作
   及可执行文件特有的 AppArmor 转换，缺少该工具时明确标为 SKIP。
2. **docker**：使用 Dockerfile 中 runner 阶段的固定 digest Python 基础镜像，
   从实际 Compose 读取 UID/GID 10001、cap_drop ALL、no-new-privileges、只读根目录、
   PID 限制和三项 tmpfs，加载原 seccomp 文件；继承默认 AppArmor，不传入替代 profile。
   在执行相同 namespace/mount/network 探针前，检查 Docker inspect 的实际安全设置，
   在容器内复核 UID/GID、CapEff/CapBnd、NoNewPrivs、Seccomp 和 AppArmor。
3. **gvisor**：只下载 `locks/runtimes.json` 锁定的官方 gVisor 包，验证 SHA512，保留
   runsc 所需 sidecar。从生产 `gvisor.py` 读取并校验 Systrap、network=none、
   gofer-network-namespace=new、ignore-cgroups、host-uds=open 参数。
   使用单当前 UID/GID 的 OCI user namespace、空 capabilities、noNewPrivileges 和
   只读 rootfs 执行 `/bin/true`，检查启动/退出、`delete --force`、空 runtime list、
   子进程退出和状态目录清理。debug 参数仅用于记录启动过程，不改变安全机制。

## 条件差异与结果含义

`production_equivalence` 始终为 **SKIP**：完整 CamAct 镜像的依赖和 CLI 不在本次范围；
`/var/lib/camact` 使用 UID/GID 10001、0700 的临时 tmpfs，替代生产数据 bind mount；
使用 Docker 默认 bridge，替代 Compose 项目 bridge。Guest 仍为 `network=none`。
这些差异在报告中明确记录，不能把通过的基础探针解释为完整镜像或存储验收通过。

**PASS** 表示该项实际成功；**FAIL** 表示实际失败；**SKIP** 表示前置失败、无法读取，
或条件不同而不能比较。若进程安全条件或 AppArmor 与 Run #5 不符，保留
`observed_status`，将相关观测标为 SKIP。任一必需项 FAIL，Workflow 失败；
必需项 SKIP，结论为 INCOMPLETE 并以非零退出。审计不可访问或未发现记录会标为 SKIP，
不单独阻止探针结论，但绝不据此认定没有策略拒绝。

`errno_source=syscall` 来自直接 syscall；`exec` 来自启动命令时的 OSError；
`stderr_inferred` 来自明确的错误文本。没有可靠 errno 时使用 null，命令退出码另存
`exit_code`，不会把退出码 1 当作 errno 1。每项包含 `stage` 和脱敏 `stderr`，
`runsc_debug` 提供有界的脱敏启动日志。

## 根据一次运行定位

| 证据 | 下一步判断 |
| --- | --- |
| host 在 user/user_mount 创建或映射阶段失败 | 优先查 Runner 内核 namespace 限额、非特权 userns 和 AppArmor userns sysctl；这还不能判断 Docker/runsc |
| host 同项 PASS，docker 失败 | 优先查外层 Docker/LSM 限制；相同安全设置下的 EPERM 本身不能区分 seccomp 与 AppArmor |
| 对应时间、comm/pid 的 AppArmor DENIED，operation 为 userns_create/mount 等 | 有 AppArmor 拒绝的直接证据；按实际拒绝操作设计后续限定修复，不在本 Workflow 放宽策略 |
| 对应进程的 SECCOMP 审计记录 | 根据 arch/syscall/code 核查 seccomp；默认 ERRNO 拒绝不保证生成审计，所以无记录不能排除它 |
| namespace/mount/net PASS，gvisor run FAIL | 查版本、stderr/debug 中的实际失败操作、OCI 映射和生产参数；仍可能是仅 runsc 使用的系统调用/LSM 限制，不能直接断言 runsc 配置错误 |
| run PASS，但 delete/state_absent/child_reaping/directory_cleanup 失败 | 启动已可行，检查 runsc 生命周期及清理；容器最终仍会被强制移除 |
| 全部基础探针 PASS | 下一次完整 CamAct 验收重点核查完整镜像、实际任务挂载和 Launch Plan；本诊断不证明六套 Harness 已通过 |

报告还记录 AppArmor/seccomp、capability 和 namespace/sysctl 状态。宿主只读尝试
`sudo -n journalctl --kernel --since …` 与 `sudo -n dmesg --since …`，仅保留该时段内
安全拒绝记录的白名单字段（含 audit_id），不上传原始内核日志、环境变量、Docker
inspect、配置、凭据或 OCI 文件。命令 stdout/stderr 只在内存，脱敏后才归档；
runsc 原始 debug 仅位于临时状态目录，脱敏后写入报告，随后随状态目录清理。

## 本地检查

脚本仅依赖 Linux、标准库 Python ≥3.11.4（tarfile data filter）、Docker Engine/Compose
（支持 `!reset`）和公开下载网络。Compose overlay 会在解析前清除 env_file、environment、
secrets、数据卷，并用 `--env-file /dev/null`，避免读取现有模型配置。

```sh
python3 -B -m unittest discover -s tests -p 'test_gvisor_diagnostics.py'
python3 -B scripts/diagnose-gvisor.py --output .validation/gvisor-local
```

没有 Docker 或宿主受限时，第二条应返回非零并保留 FAIL/SKIP 证据；不是测试通过。
不修改 sysctl、AppArmor、seccomp、capabilities、全局 Git/SSH 或现有发布 Workflow。
