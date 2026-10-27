# CamAct Docker 发布项目

**当前验收状态：NOT_READY。** 源码、锁定依赖、原生 CLI、部署入口和发布 Workflow 已准备；本机普通 Docker 容器受外层服务器权限限制，核心镜像构建/Compose/gVisor 容器集成尚未验收。完整结果和剩余门禁见 [docs/VALIDATION.md](docs/VALIDATION.md)。不要把宿主 gVisor 或合成 Mock 测试当作 Docker 测试。此轮没有上传 GitHub/GHCR，没有启动正式全量测评或付费模型请求。

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
.github/workflows/publish.yml    手动/Release 触发，构建并发布明确版本至 GHCR
tests/ / docs/                   可复现的离线测试与交接说明
```

源码从当前实际文件提取，不依赖旧 Git HEAD、旧 Conda 路径或原项目隐式文件。必要的动态 Task grader 从完整 HF 快照加载。Baseline 决策、Simulator 业务语义、GT/Rubric、Atomic 权重和 Unified Evaluator 评分逻辑保持原实现。六套执行链路、协议和恢复边界见 [EXECUTION.md](docs/EXECUTION.md)，版本与原生图片组件见 [RUNTIME.md](docs/RUNTIME.md)，逐文件来源见 [SOURCE_PROVENANCE.json](docs/SOURCE_PROVENANCE.json)。

## 新服务器条件

Linux x86_64；建议独立 Ubuntu 22.04/24.04 主机、独立部署账号、宿主 Python 3（`camactctl` 仅用标准库）、Docker Engine、Compose v2、可用的 user/PID/mount namespace 和 ptrace/Systrap。镜像目前只锁定 `linux/amd64`，评测 Python 3.13.11 在镜像内。至少预留 4 GiB 可用内存和 15 GiB 空间，较高并发及正式结果应另行扩容；下载数据约 2.35 GB，结果容量取决于运行规模。启用 cgroup、允许 Docker 的 proc 挂载；受限的 Kubernetes/共享容器可能不满足条件。

新主机可执行 `sudo bash scripts/install-host.sh` 安装已实际下载、校验和检查版本的 Docker 28.5.1、Compose 2.40.3、Buildx 0.29.1；脚本要求 Ubuntu/Debian systemd，拒绝覆盖已有 Docker，并创建 Docker 管理组。管理员需为独立部署账号授予访问权，例如在创建 `camact-deploy` 账号后执行 `sudo usermod -aG docker camact-deploy`，再重新登录该账号。已有 Docker 的服务器先运行 `docker version`、`docker compose version`、`docker buildx version`、`docker run --rm hello-world`。安装脚本本身未在本轮正式服务器执行，也不会由 `camactctl` 隐式修改宿主服务。

本方案将 runsc 和官方 CLI 一起安装在 Runner 镜像内，由可信 Runner 创建每任务 rootless gVisor；不需要将当前宿主 `.tools` 复制入库，也不需要 Docker 的 `--runtime=runsc` 注册。保留原每任务 OCI 隔离、`network=none`、只读包与当前 Task 工作区、UDS Relay。没有 Docker-in-Docker、privileged 或 Agent Docker socket。选择该方式是为了保留原路径、Relay 和 OpenClaw tmpfs 协议；Docker 内可行性仍须通过下文门禁；在权限完整的独立主机执行 `bash scripts/verify-docker.sh` 可重跑构建、15 个原生合成用例及容器重建持久化检查。

容器 capability 全部丢弃，使用 `no-new-privileges` 和仓库 seccomp 规则。Docker 28.5.1 默认 AppArmor profile 含 `deny mount,`；启用它的主机还需管理员提供限定的 Runner 策略并重测，当前仓库尚无已验证可直接加载的替代 profile。安装脚本不能保证默认宿主策略即可启动嵌套 runsc。AppArmor/SELinux 的限制应按限定规则解决；宿主直接通过 runsc 的测试不证明嵌套 Docker 已可用。

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

本目录是独立 Git 仓库，未设置远端、未推送。完成 [VALIDATION.md](docs/VALIDATION.md) 中所有 Docker 门禁后，再创建/选择 GitHub 仓库并上传。运行 `git ls-files` 和 `python3 scripts/scan-release.py --tracked` 检查本次将发布的文件。

Actions 仅在手动 `workflow_dispatch` 输入明确 SemVer（如 `0.1.0`）或正式 GitHub Release 发布时执行；构建当前代码、运行离线检查和 Compose/gVisor 合成集成门禁，成功后再发布 `ghcr.io/<owner>/<repo>:<version>` 与 `sha-<commit>`。Action 本身固定源码 Commit。不依赖 latest、不下载正式 Benchmark、不配置模型 Key、不调用真实模型。授予包写入权限的内置 `GITHUB_TOKEN` 仅用于 GHCR 登录。多阶段构建只把完整源码、运行库和锁定 CLI 放入最终镜像，编译工具留在构建阶段。

本轮只准备并本地执行 Workflow YAML/actionlint 静态检查，未触发远端发布。只有独立主机上真实 Docker 构建、启动、挂载持久化、容器内 gVisor/完整执行与评分统计、安全层扫描通过后，才可将验收状态改为 `READY_TO_PUBLISH`。
