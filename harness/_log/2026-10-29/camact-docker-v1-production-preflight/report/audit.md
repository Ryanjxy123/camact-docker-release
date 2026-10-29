# 正式 Docker 部署审查

## 结论与范围

正式项目为 `camact-docker-release/`，远端 `Ryanjxy123/camact-docker-release`，验收分支 `main`。启动时工作区干净，HEAD 为 `3c613d50c9e868b298bedb31cad173bc475ef680`；实际 fetch 后确认远端 main 为成功版本 `b0592d2f7002d0bd3a2c1e29e02e07e4e35eed85`。正式目录已用 fast-forward 同步完整 12 个提交、32 个文件，没有重新开发或覆盖已有成功修复。

本轮只修复实际验收缺口并更新文档。新候选应由用户手动执行正式 Actions；本机结果不构成新镜像 `READY_TO_PUBLISH` 证明。相邻 `camact/` 的核心源码和历史产物、两个旧诊断 worktree 均未修改。

## 实际问题与必要修改

1. 正式目录落后于成功远端，缺少具名 AppArmor 安装、生产策略握手及完整缓存/恢复门禁。直接同步成功提交，保留精确源码历史。迁移逐文件列表见 `../manifest/audit.json`。
2. 成功版本新增 `apparmor=camact-gvisor-v1` 后，两处诊断来源检查仍只接受 NNP 和 seccomp，当前诊断入口会提前拒绝生产 Compose。`scripts/diagnose-gvisor.py` 与 `scripts/diagnostic/production-plan-controller.py` 现在精确要求三项原生产选项，仍拒绝缺失、未知、unconfined 和诊断策略冒充生产策略；实际容器策略未放宽。
3. 原生合成入口只枚举 lifecycle，无法拒绝未知孤立 plan，也未完整检查生命周期字段。`scripts/native-loop-smoke.py` 直接复用成功独立诊断的 plan 分类器和生命周期字段检查，要求实际执行有调用、plan、退出及清理证据；preview 必须由 coordinator 引用证明，不能伪造 lifecycle。五套原生 CLI 的执行及统一评分保持原行为。
4. 宿主运行的源码根和 OpenClaw 系统 Python 解析路径与镜像不同。仅将当前 checkout、精确 gVisor wrapper 和源码原有 OpenClaw 预检命令的实际系统解释器解析结果映射到已验证的镜像布局；foreign 根、解释器、不同预检代码及未知 plan 继续拒绝。原始证据不重写。
5. 分类器现在被镜像内 Native 验收导入，因此 controller 不再属于诊断镜像复用的纯宿主例外，必须进入 critical-source digest；源码改变会要求重建。`tests/test_production_plan_controller.py` 与 `tests/test_gvisor_diagnostics.py` 覆盖上述失败路径，保留原断言和超时。
6. README 和 VALIDATION 仍描述未配置远端、没有受限 profile、等待旧运行验收。已更正成功证据、当前环境限制、版本差异、镜像扫描顺序和同 SHA 手动验收参数。

## 完整复用的成功机制

| 边界 | 保留的实际实现 |
| --- | --- |
| AppArmor | `camact-gvisor-v1`，ABI4、enforce；固定 profile 与六组有限 literal 宏，先编译再安装并检查精确加载名；不修改全局 LSM/sysctl/daemon |
| Runner | UID/GID 10001、零 capabilities、NoNewPrivs、仓库 seccomp、只读根文件系统、pids=4096 和有界 tmpfs；创建前后 inspect 及容器内部 `/proc`/挂载检查 |
| READY/RELEASE | 固定非特权 `docker exec` 读取实时 tmpfs；regular file、UID、大小、NOFOLLOW 校验及一次 RELEASE；不通过 `docker cp` 放行 |
| Compose | 仅创建 Runner，`create --no-build --pull never runner`，拒绝依赖；初始化 helper 显式 tools profile；CAP_ 前缀归一化 |
| 存储 | 生产 data bind 和 scratch 必须可执行；诊断受限 scratch 独立验证，未修改生产 `/tmp` 安全选项 |
| 镜像 | 公开 seccomp/profile 白名单进入上下文，配置/Secrets/数据/cache/_log 排除；不可变 image ID、OCI 版本/源码和逐层安全扫描保留 |
| HF | 固定 `53e2f450042485dfc4a3b566de6f46988c3a5661`；完整 manifest/逐文件哈希、ensure/lease 锁、当前用户 Memory 路径、断网跨容器重复复用 |
| 恢复 | 已完成任务不重放；中断任务保留 infrastructure_error；后续任务正常完成；第二次 resume 幂等；stop/kill 真实退出和残留分别记录 |

## 参考证据与版本边界

已读取成功提交的实际 Workflow、实现及测试，取得四份真实诊断 Artifact，ZIP SHA-256 全部与 GitHub 官方 API digest 一致。参考 gVisor Run `40766742381` 实际源码是 `857454199d169d5614f0dd4fe50b96a822c0d2ac`，496 项检查及 15 个 Native 用例通过。正式 Run `40780971849` 是 `b0592d2`，断网与 Compose 两轮各 336 项离线、15 个 Native、镜像扫描通过；publish job 跳过。HF Run `40785245242` 的 22,121 文件 / 2,350,271,484 字节、540 Task / 20 User Memory 检查及三容器复用通过；恢复 Run `40785245647` 的 stop/kill、退出码 3、幂等及零容器残留通过。完整原始日志 API 受认证限制，未取得日志 ZIP；已认证摘要的小型 Artifact 中包含相关阶段日志和报告。详情见 `../evaluation/reference-summary.json`。

| 环境 | Docker | Compose | Buildx | 可证明范围 |
| --- | --- | --- | --- | --- |
| 已知成功 hosted Ubuntu 24.04 | 28.0.4 | 2.38.2 | 0.38.1 | 版本来自用户此前记录；实际成功任务及产物已复核 |
| 原安装器固定版本 | 28.5.1 | 2.40.3 | 0.29.1 | 两组各 19 项实际 CLI 配置/参数检查通过；固定 Daemon 全新安装未实测 |
| 当前 Kubernetes 容器 | 无可访问 Daemon/Socket | 私有下载 CLI | 私有下载 CLI | 仅 CLI、离线与 Host gVisor；不能替代 Docker 容器验收 |

两组 CLI 均经官方摘要验证后真实执行。覆盖实际 `camactctl init`、显式 storage-init 是否自动启用 profile、默认 Runner 选择、tools profile、!reset 配置和受支持 create 参数；`--no-deps` 负控均被拒绝。Docker CLI 使用同版本官方 CE CLI 包，未把它解释为静态 Daemon 安装测试。Workflow 是 GitHub-hosted `ubuntu-24.04`，不是 self-hosted 或当前服务器；宿主 Docker/Compose 及 setup-buildx 的浮动版本需要每次真实门禁确认。

服务器 cgroup 明确位于 kubepods，当前有效 capabilities 为零，直接 mount namespace 探针 EPERM，缺 Docker Socket/Daemon、systemd 运行目录和可读 AppArmor profile 列表。单独 user namespace 可用、Host gVisor 可运行不等于满足 Docker 宿主条件。项目存储是 NFS；权限敏感测试在私有 Linux overlay 副本执行，未借用生产存储或修改系统挂载。

## 验证与未验证项

本地最终结果以 `../evaluation/local-summary.json`、`../manifest/audit.json` 及对应 `runs/` 原件为准。所有失败尝试保留；没有跳过失败测试、降低断言或延长测试超时。

| 本轮实际检查 | 结果与范围 |
| --- | --- |
| 成功版本本地基线 | Python 3.13.11，336 项，零失败/错误/跳过；捕获源码与 `b0592d2` 逐文件一致 |
| 最终完整离线回归 | 346 项，零失败/错误/跳过，148.7 秒；包含原 Usage、Baseline 合成评分、HF/锁/缓存、恢复、Runner policy、扫描和验收脚本合同 |
| 运行时与 codec | 五套官方 CLI、Node 24.14.0、runsc 20261012.0、图片辅助程序摘要匹配；真实 codec 重放及错误摘要拒绝通过 |
| Host gVisor | 27 项 namespace/mount/net 检查、生产 builder 的真实 guest marker、lifecycle 和清理通过；不作为 Docker 通过证据 |
| 五套 Native CLI | 最终 15/15：原 12 例真实执行产物由最终完整检查重新验证，OpenClaw 三模式按最终源码重新实际执行并 exit=0；真实官方 CLI、gVisor、图像证据、原评分/统计、清理及零外部模型调用通过 |
| 新生命周期逻辑独立复核 | 15 份历史真实产物兼容；150 个缺字段和 210 个安全/类型/state 反例全部拒绝；15 个受控非零退出保留原语义 |
| 两套 CLI | 各 19 项，通过；仅版本/参数/配置检查，无 Daemon 运行 |
| 静态与上下文 | 五个 Workflow 通过 actionlint 1.7.12；四个 Shell 语法与 183 个 Python AST 通过；Moby patternmatcher v0.6.0 确认 218 个上下文文件及 35 个排除探针，公开策略齐全，无符号链接、配置或归档泄漏 |

曾在 NFS 解释器及并行负载下遇到 6 项子进程超时，随后串行探针仍有 4 项错误，故未将问题简单归为并发。把相同 Python/依赖的 5,198 个文件、223.6 MB 完整复制到私有 overlay 后，逐文件 SHA-256、版本、ldd、锁哈希和 `pip check` 通过；十轮启动均值从 0.298 秒降为 0.104 秒，完整回归在原 60 秒用例上限内通过。首轮失败、串行探针、搬迁对照和最终成功原件全部保留。没有修改项目依赖、锁或超时。

OpenClaw 首轮真实执行发现宿主系统 Python 路径与镜像不同，修复仅涉及验收适配。后续一次重跑因本地私有 TMPDIR 过长触发 `AF_UNIX path too long`，在发起 Agent/Simulator 请求前终止；改用短私有临时路径后，三模式全部实际通过。两个失败批次与原始 validation 均保留，没有改写旧记录。最终检查对应 12 例保留产物和 3 例新执行，不把产物重放描述为重新执行 15 次。

追踪源码/精选报告扫描和原始归档文本扫描未发现凭据候选；下载的公开工具按官方摘要验证。扫描仅证明已覆盖的格式模式，不宣称能识别任意未知密钥格式。构建上下文未包含原始日志、数据、配置、缓存或 `_log`。项目既有产物检查器对正式项目根运行结果为 **ROOT_ARTIFACT_LEAK=0**，原始输出保存在 `runs/root-artifact-check.log`。

本轮没有在真实 Docker 中重验：最终镜像构建/扫描、具名 profile 加载、UID/Secrets/tmpfs/data bind 实际挂载、READY/RELEASE、容器内 gVisor、完整 HF 跨容器下载/复用、stop/kill/resume、固定版本新宿主全新安装。离线 Docker 协议 stub 只证明验收脚本的逻辑，不能将其计为真实 Docker 通过。

Canonical Benchmark、Task、GT/Rubric、Simulator、Baseline、Unified Evaluator、六套 Harness 核心决策和依赖锁均未改变。没有正式 Benchmark 执行、付费模型、Actions 触发或 GHCR 发布。

## 手动验收顺序

1. 选择 `main` 的最终提交，手动运行 **Verify and optionally publish CamAct** / `publish.yml`：`version=0.1.0-rc.1`、`publish=false`。
2. 成功后，在同一完整提交上运行 `verify-full-cache.yml` 与 `verify-recovery.yml`：`image_run_id=<新的成功 publish Run ID>`、`expected_source_revision=<最终完整 Commit SHA>`、`version=0.1.0-rc.1`。镜像 Artifact 只保留 3 天；及时运行后续两项。
3. 需要排障时可运行 `diagnose-gvisor.yml`，先用 `scope=production-plan`、`policy=candidate`、`native_matrix=true`，`reuse_image_run` 留空以构建当前源码。诊断无法代替正式验收，baseline 预期拒绝也不能记为生产通过。

在同一新候选的所有真实门禁完成之前，不宣称该候选 READY_TO_PUBLISH；本轮继续保持不发布。
