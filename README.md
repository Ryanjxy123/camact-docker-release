# CamAct Docker 发布项目

**当前源码可进入下一次手动验收，保持 `publish=false`。** 服务器正式目录已同步成功版本 `b0592d2f7002d0bd3a2c1e29e02e07e4e35eed85` 的完整 Docker/gVisor 修复；该版本的正式 Docker、完整 HF 缓存和 stop/kill/resume 已有真实 Actions 证据。本轮补齐诊断策略漂移及 Native plan 生命周期验收，修改后的候选仍需重新构建并在 Actions 验证。当前 Kubernetes 容器不能提供真实 Docker 验收；不以本地静态或离线测试宣称新镜像 `READY_TO_PUBLISH`。证据及边界见 [docs/VALIDATION.md](docs/VALIDATION.md)。未运行正式 Benchmark、调用付费模型或发布 GHCR。

## 职责与源码

GitHub 保存测评源码、部署脚本与锁文件；GHCR 保存运行环境镜像；HF 保存 Benchmark。镜像不含 Benchmark、历史结果、个人配置或真实密钥。

```text
camactctl                        宿主统一入口，自动调用 Docker Compose
Dockerfile / compose.yaml        非 root Runner、持久化挂载、外部 Secrets
release/                         下载完整性、三角色配置、范围选择与容器入口
deployment/                      现有持久化调度器的部署适配与原统计函数
benchmark/{benchmark_runner,services,evaluator}/
                                 原 Baseline Loop、Simulator、业务 Mock、动态评分
harness/baseline harness/        原 Canonical Baseline 入口
harness/claude code/             原 Claude 原生运行器与 Relay
harness/camact_multi_harness_v1/  五套官方 CLI 的工具、Session 与 gVisor Adapter
harness/camact_{prompt_parity_v1,compatibility_v2,token_usage_v1}/
                                 公共 Prompt、标准产物、Usage/Token 统计
evaluation/camact_eval/          原 Unified Evaluator、Strict、图片执行证据
locks/                           精确 Python/npm/Node/runsc/Rust 版本与校验值
scripts/                         安装、初始化、版本检查、合成 Smoke、安全扫描
config/models.env.example        无真实模型/地址/密钥的配置模板
deploy/                          限定 namespace/Systrap 系统调用的 seccomp 配置
.github/workflows/              手动触发，默认只验证；显式选择后才允许发布 GHCR
tests/ / docs/                   可复现的离线测试与交接说明
```

源码从当前实际文件提取，不依赖旧 Git HEAD、旧 Conda 路径或原项目隐式文件。必要的动态 Task grader 从完整 HF 快照加载。Baseline 决策、Simulator 业务语义、GT/Rubric、Atomic 权重和 Unified Evaluator 评分逻辑保持原实现。六套执行链路、协议和恢复边界见 [EXECUTION.md](docs/EXECUTION.md)，版本与原生图片组件见 [RUNTIME.md](docs/RUNTIME.md)，逐文件来源见 [SOURCE_PROVENANCE.json](docs/SOURCE_PROVENANCE.json)。

## 新服务器条件

Linux x86_64；建议独立 Ubuntu 24.04 主机、独立部署账号、宿主 Python 3（`camactctl` 仅用标准库）、Docker Engine、Compose v2、已启用的 AppArmor 与支持 ABI4/userns 的 AppArmor 4 以上 parser，以及可用的 user/PID/mount namespace 和 ptrace/Systrap。其他 Ubuntu/Debian 主机须满足相同条件；AppArmor 3 的语法检查不构成生产兼容证明。镜像目前只锁定 `linux/amd64`，评测 Python 3.13.11 在镜像内。至少预留 4 GiB 可用内存和 15 GiB 空间，较高并发及正式结果应另行扩容；下载数据约 2.35 GB，结果容量取决于运行规模。启用 cgroup、允许 Docker 的 proc 挂载；受限的 Kubernetes/共享容器可能不满足条件。

新主机可执行 `sudo bash scripts/install-host.sh` 安装 AppArmor 软件包、加载固定 Runner 策略，再安装已锁定并校验的 Docker 28.5.1、Compose 2.40.3、Buildx 0.29.1；脚本要求 Ubuntu/Debian systemd，拒绝覆盖已有 Docker，并创建 Docker 管理组。ABI4/profile 加载失败时立即停止。管理员需为独立部署账号授予访问权，例如在创建 `camact-deploy` 账号后执行 `sudo usermod -aG docker camact-deploy`，再重新登录该账号。已有 Docker 的服务器检查三个版本后，独立运行下方策略安装命令；无需重装 Docker。`camactctl` 不会隐式修改宿主服务或策略。

成功 Actions 使用 GitHub-hosted `ubuntu-24.04`，不是当前服务器或 self-hosted Runner。此前记录的成功环境 Docker 28.0.4、Compose 2.38.2、Buildx 0.38.1 与上述安装器版本不同；Workflow 使用宿主 Docker/Compose，Buildx setup 未固定版本。两组 CLI 的配置/参数检查不能证明两个 Daemon、内核与 AppArmor 环境等价。固定版本宿主的全新安装和 Docker 内 gVisor 尚未实测，须在目标主机执行全部门禁；不能把安装器的下载/版本校验解释为部署成功。

本方案将 runsc 和官方 CLI 一起安装在 Runner 镜像内，由可信 Runner 创建每任务 rootless gVisor；不需要将当前宿主 `.tools` 复制入库，也不需要 Docker 的 `--runtime=runsc` 注册。保留原每任务 OCI 隔离、`network=none`、只读包与当前 Task 工作区、UDS Relay。没有 Docker-in-Docker、privileged 或 Agent Docker socket。选择该方式是为了保留原路径、Relay 和 OpenClaw tmpfs 协议；Docker 内可行性仍须通过下文门禁；在权限完整的独立主机执行 `bash scripts/verify-docker.sh` 可重跑构建、15 个原生合成用例及容器重建持久化检查。

Runner 保留 UID 10001、capability 全部丢弃、`no-new-privileges`、仓库 seccomp、只读根文件系统及原 pids/tmpfs 限制，Compose 显式使用具名 enforce 策略 `camact-gvisor-v1`。管理员在启动前加载仓库的固定策略：

```bash
# 使用 .env 中 CAMACT_DATA_DIR 对应的宿主绝对目录；目录可尚不存在
sudo bash scripts/install-gvisor-policy.sh install --data-dir /srv/camact-data
sudo bash scripts/install-gvisor-policy.sh --check-roots --data-dir /srv/camact-data
# 仅离线检查源文件与宏，不证明内核已加载或运行时可用
bash scripts/install-gvisor-policy.sh check --data-dir /srv/camact-data
```

未传 `--data-dir` 时检查仓库 `.data`。安装器仅向 `/etc/apparmor.d/camact-gvisor-v1` 写入此固定 profile，编译成功才加载，并核对精确名称与 enforce 模式；不修改 `docker-default`、Docker daemon、全局 sysctl 或 LSM 状态。策略保留原 proc/sys 和网络限制，只允许锁定 runsc 的明确 staging、state、任务工作区与只读包挂载。Personal Memory 的挂载源始终是当前 Task 的 album 副本，cache 路径仅作为只读别名目标；用户/任务关联仍由原 builder 的 allowlist 保证。

默认支持 `/var/lib/camact/{results,benchmark,scratch}`、`scratch/gvisor` 及下方固定 Benchmark commit。原 CLI 的自定义根目录与仓库/版本仍可使用，但必须先由管理员显式安装相应策略配置，再以相同参数检查。例如：

```bash
sudo bash scripts/install-gvisor-policy.sh install --data-dir /srv/camact-data \
  --results-root /var/lib/camact/results/subdir \
  --cache-root /var/lib/camact/cache/project/benchmark \
  --repo-id OWNER/DATASET --revision <40位小写commit>
sudo bash scripts/install-gvisor-policy.sh --check-roots --data-dir /srv/camact-data \
  --results-root /var/lib/camact/results/subdir \
  --cache-root /var/lib/camact/cache/project/benchmark \
  --repo-id OWNER/DATASET --revision <40位小写commit>
```

每类最多 8 个去重后的显式值（含保留的默认值）；还可用 `--scratch-root`、`--state-root` 配合相应容器环境变量。根目录必须是 `/var/lib/camact` 下的普通绝对 literal 路径，拒绝 glob、路径回退、Secret/系统目录和映射后的软链接；各根后仍限定固定 release/smoke/preflight 层级。变更参数应重新安装完整所需集合；安装不会自动合并旧的额外权限。遗漏配置时 `--check-roots` 失败，不能据此宣称自定义路径受支持。

Ubuntu 的裸宿主 userns 探针可能受到其自身 AppArmor 上下文限制；其失败应保留为诊断结果，不能改记为通过。正式门禁须在真实 Compose Runner 中核验上述策略、运行生产 builder、5 个 CLI 与 cleanup，并完成原合成验收。profile 成功加载及宿主直接通过 runsc 均不能替代这些检查。

## 初始化、构建与模型配置

```bash
./camactctl init
# 编辑 .env 选择镜像、持久化根目录；编辑 config/models.env 选择模型和端点
./camactctl build
# 或在 .env 写 CAMACT_IMAGE=ghcr.io/<owner>/<repo>:<version> 后：
./camactctl pull
./camactctl secret agent
./camactctl secret judge
./camactctl secret simulator
./camactctl check
```

`secret` 不回显，值通过 stdin 交给无网络的初始化容器，写入宿主外部 Secret 文件，权限为 UID 10001/0400；Runner 以 UID 10001 读取。Compose 不把真实 Key 放入镜像、命令参数或配置快照。`.env`、`config/models.env`、`.secrets`、`.data` 均被 Git/Docker 构建上下文排除。初始化只创建/校正专用顶层存储目录，不递归重写已有结果。

共享同一 Linux UID 的人员不能依靠 0600 相互隔离；具有 Docker/sudo 管理权限的人员也能读取容器凭据。生产部署必须使用独立账号和可信宿主管理边界，不能把当前共享 UID 环境称为密钥隔离。

三角色分别填写：

| 角色 | 配置变量 | 原实现支持 |
|---|---|---|
| Agent | `AGENT_MODEL`、`AGENT_BASE_URL`、`AGENT_PROTOCOL_<HARNESS>` | 按所选官方 CLI 协议 |
| Judge | `JUDGE_MODEL`、`JUDGE_BASE_URL`、`JUDGE_PROTOCOL` | `openai-chat` |
| Simulator | `SIMULATOR_MODEL`、`SIMULATOR_BASE_URL`、`SIMULATOR_PROTOCOL` | `openai-chat` |

Key 由 `*_API_KEY_FILE` 注入；默认 Compose 已分别映射三个 Secret。三角色可以共享或使用不同模型、URL、Key。官方 CLI 内始终使用占位 Key，由可信 Relay 注入真实凭据。

Agent 默认协议：Baseline Chat、Claude Anthropic Messages、Codex Responses、dsh DeepSeek Messages、OpenCode/OpenClaw Anthropic Messages。网关需要提供对应协议；协议不兼容会在发起测评前拒绝。可按 Harness 覆盖，例如 `AGENT_MODEL_CODEX`、`AGENT_BASE_URL_CODEX`、`AGENT_PROTOCOL_CODEX`。原生模型能力用 `AGENT_MODEL_OPTIONS_<HARNESS>` JSON 配置，详见 [EXECUTION.md](docs/EXECUTION.md)；dsh 图片任务应声明 `inputModalities` 包含 `image`，不能只把图片能力写进 Prompt。

三个角色均有 `*_TIMEOUT_SECONDS`、`*_MAX_OUTPUT_TOKENS`、`*_PARAMETERS`；只接受原适配器实际支持的参数。Judge/Simulator 保留 `temperature=0`，不能任意改写采样策略。原生 CLI 的重试行为仍由其官方实现负责。

## Benchmark 下载与固定版本

默认 Dataset 为 `Ryanjxy/CamAct-Benchmark`，固定 Commit：

```text
53e2f450042485dfc4a3b566de6f46988c3a5661
```

```bash
./camactctl download
./camactctl download --offline
# 可选：--repo-id OWNER/DATASET --revision <40位commit>
```

`check`/`run` 自动获取指定版本；未完整下载时绝不启动测评。下载器用 `huggingface_hub` 获取该 Commit 的完整文件清单，在宿主持久化缓存中按仓库/Commit 分目录保存，校验每个 Git blob SHA1 或 LFS SHA256。完整才写 `complete.json`；缺失/损坏自动补齐，下载失败不写完成标记。复用前校验本地内容，完整缓存不重复下载，也不需要在线访问 HF。

默认不读取个人 HOME/HF Token。公共仓库匿名限流时，可将独立只读 Token 作为额外 Secret 挂载，并显式传入 `--token-file /run/secrets/hf_token` 或设置 `HF_TOKEN_FILE`。不要写入 Git 或 Docker build args。下载重试遵守 Retry-After；多次失败保留已验证文件供下次继续。

运行父进程和 Worker 持有固定 Commit 的共享锁，下载/修复需要独占锁；不会在运行中切换版本。Benchmark 数据目录通过链接映射到原 `benchmark/` 数据位置，源码 `services/` 等仍来自镜像，不会被数据挂载覆盖。

## 选择范围、查看结果和恢复

```bash
./camactctl run --harness all --all-users --parallel 2 --run-id full-v1
./camactctl run --harness baseline,codex --user USER_ID --parallel 2
./camactctl run --harness claude-code,opencode --users USER_1,USER_2 --parallel 2
./camactctl run --harness dsh,openclaw --user USER_ID --detach --run-id subset-v1
./camactctl status --run-id subset-v1
./camactctl logs --run-id subset-v1 --lines 100
./camactctl resume --run-id subset-v1
```

这些是正式测评命令，按选择范围产生模型调用；本轮未执行它们。`all` 包含六套 Harness；支持任意无重复子集，`--user`/`--users` 按实际 HF ID 选择，每个 User 的全部 Tasks。`--parallel` 是全局 Task 并发上限，范围 1–36。未指定 Run ID 时生成唯一 ID；已有 ID 拒绝覆盖。`status/logs/resume` 不给 ID 时使用本地最近一次记录。

中断后已确认评分不会重复执行。仍活跃的 Worker 按锁、PID/起始 Tick/Boot ID 识别；身份不确定会停止派发。中断但未确认结果的付费执行不会自动重新运行。原基础设施重试默认 1 Attempt，开始时明确 `--infrastructure-attempts 2` 或 `3` 才允许已确认终结的失败有限重试；可复用的冻结执行证据走原 Judge-only 流程。详见 [恢复边界](docs/EXECUTION.md)。

持久化根目录由 `.env` 的 `CAMACT_DATA_DIR` 指定，可放独立磁盘：

```text
benchmark/       HF 按仓库/Commit 隔离的缓存和完整标记
results/<ID>/   run_manifest.json、formal_config.json、原每任务结果与证据
logs/           独立日志扩展位置；当前调度日志随 results/<ID>/audit 保留
cache/          扩展缓存
scratch/        gVisor 临时状态、任务临时空间
checkpoints/    持久化检查点扩展位置；当前恢复依据 results 内清单/锁
```

结果根目录可通过 `CAMACT_DATA_DIR` 切换整块存储；容器入口还支持 `--results-root /var/lib/camact/results/subdir`。查询/恢复使用相同参数。宿主绑定目录在容器删除、重建后保留；同一 Run ID 有独占调度锁，多个实例不能覆盖。

`results/<ID>/final_report.md`、`aggregate/summary.json` 展示 Score、Strict、Request 和 Input/Output/Total Token；单任务 `users/.../attempt_*/run/result.json` 保留正式结果，`token_usage/accounting_v3/` 保存原始采集和统计。未知 Token 字段保留 N/A，不用 Turn 数估算。清单记录镜像 ID/版本、源码 SHA、HF Commit、Harness 版本和不含 Key 的模型配置标识。

升级镜像先改 `.env` 的明确版本，再 `./camactctl pull`；切换数据版本改 `config/models.env` 的 `BENCHMARK_COMMIT` 或传 `--revision`，启动新 Run ID。旧任务恢复须使用原镜像/源码、原 Benchmark 和相同模型设置；已有缓存和结果无需删除。

## 安装版本与离线检查

Python 固定 3.13.11；原正式环境为 Conda，镜像从固定 digest 的官方 Python 镜像构建，不复制 Conda 环境。`locks/requirements-runtime.lock` 固定全部运行依赖和 Linux cp313 wheel 哈希，保留原 `requirements-evaluator.lock` 精确评分门禁。Node 24.14.0、runsc 20261012.0；五套 CLI 为 Claude 2.1.160、Codex 0.147.0、OpenCode 2.0.32、dsh 0.2.1-rc.2、OpenClaw 2026.6.11。

构建时自动执行 `bash scripts/install-runtimes.sh`，在镜像 `.tools/<name>` 中从公开官方包执行固定 npm `ci`，并构建原生评分图片辅助组件；这些正是 gVisor 实际挂载/执行的位置。命令、安装来源、依赖与版本验证见 [RUNTIME.md](docs/RUNTIME.md)。

```bash
docker compose run --rm --entrypoint python runner -B scripts/check-runtimes.py --sandbox
docker compose run --rm --entrypoint python runner -B scripts/check-codecs.py
docker run --rm --network=none --entrypoint python camact:local -B scripts/run-offline-tests.py
python3 scripts/scan-release.py --tracked
python3 scripts/scan-image.py --archive /path/to/docker-save.tar
```

`scripts/native-loop-smoke.py` 使用合成 Task、本地模型协议服务器和真实官方 CLI 验证原生工具/续轮；不连接外部模型，但需要完整运行时及可用 gVisor。测试模式和参数先查看其 `--help`，结果写入独立验证目录，不混入 Benchmark。

## 常见问题

| 现象 | 检查与处理 |
|---|---|
| Docker `unshare`/proc mount/cgroup 错误 | 外层服务器限制；在具备完整 Docker 权限的独立 Linux 主机重测，不能用宿主 Smoke 替代 |
| 下载 429/连接失败 | 等待 Retry-After 后重试；缓存会续传；必要时显式挂载只读 HF Token |
| Key 文件权限/空内容 | `./camactctl secret ROLE` 重新注入；不要把真实 Key 写进模板 |
| 模型协议被拒绝 | 按每套 CLI 原生协议配置网关/覆盖地址；Judge/Simulator 只支持 Chat |
| OpenClaw HOME 被拒绝 | 保留 Compose 私有 256 MiB `/run/camact/openclaw` tmpfs、UID 10001/0700；不放宽原门禁 |
| CLI/图片 SHA 不符 | 使用锁文件重新构建；不要替换全局 CLI 或手工跳过图片证明门禁 |
| 配置/源码改变后无法恢复 | 用原镜像和配置恢复，或创建新 Run ID |
| 磁盘、内存或权限不足 | 扩容 `.env` 挂载目录，降低并发；启动检查会验证可写/fsync、磁盘和内存 |

## GitHub Actions 发布

本目录是独立 Git 仓库，正式远端为 `Ryanjxy123/camact-docker-release`，手动验收分支为 `main`。运行 `git ls-files` 和 `python3 scripts/scan-release.py --tracked` 检查提交内容；本地配置、数据、凭据、原始审计产物及 `.validation` 不随源码上传。精简审计报告按项目规范保存在 `harness/_log/`，并被 Docker 构建上下文排除。

上传后的操作步骤：

1. 在仓库的 Settings → Actions 中允许执行本仓库 Workflow；无需添加 Agent、Judge、Simulator 或 HF Secrets。
2. 打开 Actions → **Verify and optionally publish CamAct** → **Run workflow**，选择上传的分支，输入 `version=0.1.0-rc.1`，保持 `publish=false`。
3. `ubuntu-24.04` Runner 依次扫描源码、构建并加载 `linux/amd64` 候选镜像、检查不可变身份并扫描镜像层，然后运行断网容器测试、Compose/gVisor、图片 codec、15 个原生合成用例及容器重建持久化门禁。任一步失败，Workflow 失败；默认验证任务没有包写权限，也不登录或推送 GHCR。
4. 核对 [VALIDATION.md](docs/VALIDATION.md) 中的剩余门禁和宿主 AppArmor 条件，完成全部验收并复核结果后，才以正式版本重新手动运行并选择 `publish=true`。此次仍会完整重建和重验，只推送本次通过扫描及测试的同一本地镜像，不另行构建。当前状态只适合执行第 2 步的验证。

普通 Push、Tag 和 GitHub Release 均不会触发此 Workflow。入口 `publish.yml` 调用同 Commit 的 `verify-candidate.yml`；验证分支只有 `contents: read`，显式发布分支才额外授予 `packages: write`。Checkout 不保留 Git 凭据，第三方 Action 固定源码 Commit；内置 `GITHUB_TOKEN` 仅在门禁成功后用于 GHCR 登录。镜像仅使用明确版本和 `sha-<commit>` 标签，不使用 latest；验证不下载正式 Benchmark、不配置模型 Key、不调用真实模型。多阶段构建把源码、运行库和锁定 CLI 放入最终镜像，编译工具留在构建阶段。

`scripts/scan-image.py` 在 Docker 门禁和发布前扫描 `docker save` 归档中的 OCI config、Env、History、Labels 以及每一层原始文件；即使文件随后被 whiteout 删除，也会被检查。工具只输出路径和问题类型，不输出候选密钥；归档结构异常时失败关闭。`bash scripts/verify-docker.sh` 会在构建后自动调用它，并验证镜像 ID、OCI 版本/源码标签、持久化 Benchmark 挂载和两个新容器的离线缓存复用。设置 `CAMACT_VERIFY_FULL_BENCHMARK=1` 可在已下载完整缓存的主机上额外执行固定 Commit 的容器内离线哈希检查。合成缓存检查只证明挂载/复用机制，不代替完整 Benchmark 验证。

扫描诊断直接显示在 Actions 日志中，并在 `docker-verification-diagnostics` artifact 中保留脱敏扫描 JSON 和阶段摘要。已核实的官方依赖误报记录在 `locks/image-scan-exceptions.json`，必须同时匹配路径、文件哈希和具体命中指纹；更新依赖或基础镜像时需重新核验来源。未知命中、文件变化及扫描错误仍会阻断发布。

本轮未触发任何 Actions 或发布。下一次先在 `main` 手动运行 **Verify and optionally publish CamAct**（`publish.yml`），设置 `version=0.1.0-rc.1`、`publish=false`。成功后，在同一完整源码 SHA 上分别运行 **Validate the complete pinned HF cache**（`verify-full-cache.yml`）及 **Validate synthetic Docker stop and kill recovery**（`verify-recovery.yml`），输入新的 `image_run_id`、相同 `version` 和当前完整 `expected_source_revision`；参数以对应 Workflow 的输入定义为准。旧 `b0592d2` 镜像不能用于新 SHA 验收。两个入口见 [完整缓存验收](docs/FULL_CACHE_VALIDATION.md) 与 [恢复验收](docs/RECOVERY_VALIDATION.md)。诊断入口可独立排障，但不能代替正式门禁。只有同一候选的全部真实 Docker、HF 和恢复门禁通过后，才可确认该候选 `READY_TO_PUBLISH`。
