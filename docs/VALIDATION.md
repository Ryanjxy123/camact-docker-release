# 发布验收记录

验收日期：2026-10-28。当前结论：**NOT_READY**。

发布源码、部署文件、六套 Harness、锁定安装和本地合成执行已准备。当前服务器的外层隔离阻止 Docker 完整镜像构建和普通容器启动，因此尚未满足 `READY_TO_PUBLISH` 的核心 Docker 门禁。宿主 gVisor 测试通过不代表容器内通过。

本轮未上传 GitHub/GHCR、未触发远端 Actions、未启动正式 Benchmark 测评，未调用付费模型。真实 HF 下载仅用于指定版本的本地完整性验证；没有重复远端内容审计。

## A–F 验收范围

| 项目 | 实际结果 | 验证边界 |
|---|---|---|
| A 源码完整性 | PASS | 静态依赖闭包、动态评分导入、完整 Baseline CLI 和三类合成任务通过；没有未解决的必需模块。正式来源逐文件哈希见 SOURCE_PROVENANCE.json |
| B Python 依赖 | PASS（宿主干净 venv） | Python 3.13.11、35 个依赖带 wheel 哈希重新安装，pip check 与原 formal evaluator gate 通过；尚未在最终 Debian 镜像中运行 |
| B Docker 镜像 | BLOCKED | 实际执行了构建，但镜像层注册被宿主权限拒绝；没有完整镜像或成功启动结果 |
| B Compose | PARTIAL | 官方 Compose 2.40.3 配置解析及变量/引号/带空格挂载路径验证通过；实际挂载、网络、容器重建持久化未通过验收 |
| C 六套 Harness | PASS（宿主合成任务） | Baseline 单轮/多轮/History；五套真实官方 CLI 在真实 gVisor 中的 15 个同类用例全部通过。没有使用真实模型或正式任务 |
| C 沙箱生命周期 | PASS（宿主） | 五套固定 CLI 的启动/版本/退出、沙箱清理、Relay/Mock、原生工具/读图和续轮通过；Docker 内同项待验收 |
| D HF 管理器 | PASS（宿主完整缓存） | 固定 Commit 的 22,121 文件、2,350,271,484 字节真实下载及逐文件 Git blob/LFS 哈希校验通过；离线 ensure/lease 完整复用且零网络调用。16 项失败/版本/缺失/损坏/锁等测试通过；不是容器内下载验证 |
| E 评分和统计 | PASS（合成任务） | Unified Evaluator、Atomic、Score、Strict、图片证据、Agent/Simulator/Judge 物理请求和精确 Token 统计通过；不是正式 Benchmark 成绩 |
| F 发布源码安全 | PASS（本地检查） | 发布源代码模式扫描、独立 Git 与 Docker 上下文白名单；不包含 Benchmark 数据、旧产物、安装目录或个人配置。最终追踪文件扫描单独留证 |
| F 凭据隔离 | PASS（宿主 gVisor 探测） | 十种合成三角色/覆盖/HF 凭据未进入 Guest、Launch Plan 或生命周期记录；原生 CLI 使用占位 Key |
| F 最终镜像层 | NOT_TESTED | 没有可扫描的完整镜像，不能声称镜像层安全扫描通过 |
| GitHub Workflow | PASS（本地静态检查） | actionlint 1.7.12 通过；发布前先扫描已构建本地候选镜像，再强制 Compose/gVisor 合成集成门禁，最后只推送已扫描候选。未执行远端 Workflow |

## 测试证据

原始证据保存在本地 Git 忽略目录，不随发布上传，也不打入镜像。以仓库为当前目录：

| 证据 | 路径 |
|---|---|
| 干净 Python 131 项测试，零失败/错误/跳过 | `.validation/source-integration/final-offline-image-security/offline-tests.json`；公开入口 `scripts/run-offline-tests.py`，含 5 项 Docker 归档安全扫描测试 |
| 依赖闭包与动态导入 | `.validation/source-integration/import-closure.json` |
| 原代码逐文件比较 | `.validation/source-integration/source-compare.json` |
| Compose 真实解析，不启动容器 | `.validation/source-integration/compose-config-paths.json` |
| Docker 官方 Moby ignore parser、上下文及隔离复制测试 | `.validation/2026-10-28/camact-docker-v1-packaging/docker-context-audit/` |
| 15 项原生 CLI 最终矩阵及历史尝试说明 | `.validation/2026-10-28/camact-docker-v1-packaging/native-runtime-matrix.json`、`native-runtime-report.md` |
| CLI/gVisor 版本、15 个图片依赖摘要、十变量 canary | 同目录 `runtime-sandbox-check-002.json` |
| 图片编码重放与错误摘要拒绝 | 同目录 `codecs-smoke.json` |
| 带哈希 Python 重新安装 | 同目录 `python-hashed-install.log` |
| 官方 Debian ripgrep 的校验、实际搜索参数测试 | 同目录 `ripgrep-bookworm-check/report.json` |
| Docker 实际失败 | 同目录 `docker-build.log`、`docker-build-rootless.log`、`docker-container-probe*.log` |
| Workflow 静态检查 | 同目录 `actionlint.log`，退出码 0、无诊断 |
| HF 指定版本完整下载 | 同目录 `benchmark/real-download.json` |
| HF 全量缓存离线复用与只读范围选择 | 同目录 `benchmark/offline-reuse-and-layout.json` |
| 最终 Git 追踪源码安全扫描 | 同目录 `security-scan-tracked.json` |
| Docker 归档扫描器离线测试 | `tests/test_image_security.py`；当前仅合成归档，真实镜像扫描待 Docker 构建门禁 |
| 正式目录保护 | `.validation/source-integration/formal-protection.json` |

五套最终矩阵共 91 次本地 Agent 协议请求、15 次 Simulator 请求、1,590 个确定性 fixture Token。每例验证原生 shell/图片能力、合法资源视图、非法业务动作拒绝、公共 Prompt、visual_verified、Atomic/Strict、精确请求与 Token、完整 Usage、生命周期退出和状态清理；这些都是合成协议证据。此前失败尝试保留在忽略目录，最终矩阵记录其原因，包括 OpenClaw 并发启动超时及随后顺序重跑通过。

最终构建上下文使用与 Docker 28.5.1 依赖一致的官方 Moby patternmatcher v0.6.0 解析，包含 192 个文件、2,740,080 字节；35 个根目录/嵌套凭据、数据和缓存探针全部排除。严格按 COPY008 清单复制到隔离目录后，在无 `.tools`/原配置/原项目路径的环境运行公开入口，131 项测试全部通过，测试前后所有 COPY 文件 SHA-256 不变。COPY008 包含镜像归档扫描器及更强的 Docker 门禁脚本；新增文件的 5 项扫描器回归覆盖干净二进制、配置/History/Label 凭据、已删除层中的凭据、个人配置路径和损坏归档失败关闭。汇总为同验证目录的 `runtime-context-final-report.json`；该测试验证 COPY 源码闭包，仍不属于 Docker 容器测试。

真实 HF 验证使用 Python 3.13.11、huggingface_hub 1.13.0，固定 Commit `53e2f450042485dfc4a3b566de6f46988c3a5661`；完整清单 SHA-256 为 `8dfc42da68938abcfac3b379659fbaa3b8d9c96eae39ef85662a2a92037f4e60`。下载结束后，以失败 stub 覆盖 HF 元数据、下载、客户端、网络连接和 Token 读取入口，再执行离线 ensure 和只读 lease，两次完整本地哈希均通过，外部调用全部为零。只读范围选择确认 20 Users、540 Tasks、六套 Harness 共 3,240 个待执行 Slot；没有 prepare/run、模型调用或正式测评启动。该缓存仅保留在本地忽略目录，未加入 Git 或 Docker 上下文。

## Docker 阻塞原因

本机起初没有 Docker。本轮将官方 Docker 28.5.1、Compose 2.40.3 下载到验证目录，使用专用临时 daemon/socket/data-root 尝试真实构建，未更改正式服务。

1. 普通 daemon 的镜像层注册失败：`unshare: operation not permitted`。
2. 验证专用 user namespace 内可解包探针镜像，但普通容器受只读 cgroup 限制；rootless 探针在 `/proc` mount 处遭遇 `operation not permitted`。
3. 实际 CamAct Docker 构建发送约 2.757 MB 的白名单上下文并拉取固定 Rust 镜像，随后 `/etc/gshadow` 的 UID/GID ownership 设置被拒绝，无法注册基础镜像层。

这些发生在正式镜像能执行 RUN 指令之前。此处没有把验证用 namespace helper 作为生产部署方案，没有添加 privileged、Docker socket 或放宽 Agent 隔离。验证专用 daemon 已停止，失败日志保留。

另经 Docker 28.5.1 官方依赖的 AppArmor profile 源码核实，默认配置包含 `deny mount,`。启用该 profile 的新主机还需管理员提供限定的 Runner 策略并实测嵌套 runsc；本仓库尚无已验证可直接加载的替代 profile。单独允许 seccomp 调用、安装 Docker/CLI 或通过宿主 gVisor 测试都不足以解决该项。

## 正式目录保护

正式 `camact/` 的 258 个源码/配置文件均与开始时的 SHA-256、mtime 一致，无丢失。运行依赖子集 145 个文件中 137 个字节一致，8 个发布适配涉及运行时路径、原生图片构建摘要、tmpfs、环境凭据过滤及旧个人路径防护判断的通用化；外层调度/入口等适配另记在 `SOURCE_PROVENANCE.json`。个人路径清理后的通用防护另有回归测试。

Baseline 决策、Simulator 业务协议、Unified Evaluator 评分规则保持原代码。未复制、修改或清理正式 Benchmark、GT、Rubric、历史运行记录及结果。此保护检查没有重新审计 Benchmark 内容。

## 尚需完成的发布门禁

在权限完整的独立 Linux x86_64 Docker 主机上，先阅读 README，再执行：

```bash
bash scripts/verify-docker.sh
```

脚本构建最终镜像，检查 Compose、容器内固定版本与真实 gVisor、图片 codec、离线测试、15 个原生合成执行以及跨两次容器创建的持久化。只用本地确定性协议服务，不调用配置的真实模型。CI 在推送 GHCR 前同样要求该门禁成功。出现 AppArmor/namespace/seccomp 错误应修复限定宿主规则并重测。

还需在最终 Docker 镜像中确认 HF 下载与缓存挂载、运行配置及源码版本记录、Docker 终止/恢复行为，并对最终镜像的环境、文件、构建历史和每层执行敏感信息扫描。宿主完整 HF 缓存验证和 Git 源码扫描不能替代这些容器门禁。

以上证据齐全后才能改为 `READY_TO_PUBLISH`。当前目录可继续本地审查；本轮不会创建远端仓库或执行发布。
