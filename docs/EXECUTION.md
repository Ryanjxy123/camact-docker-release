# 执行链路与恢复边界

发布源码来自当前实际工作的 CamAct 文件，而非旧 Git HEAD；原安装没有可用的 Git 仓库，因此发布目录记录逐文件 SHA-256，并建立独立 Git 历史。Docker 适配只改变外层配置、数据路径、调度范围和运行环境，不改 Agent 决策、Task/GT/Rubric、Simulator 业务协议或 Unified Evaluator 评分规则。

## 六套 Harness

| 选择名 | 原有实际执行链路 | Agent API 协议 |
|---|---|---|
| `baseline` | `camact_harness` → `baseline_harness.cli` → `observed_runner` → `benchmark_runner/run_model.py --aep-mode baseline` | `openai-chat`、`anthropic-messages` |
| `claude` / `claude-code` | `camact_multi.cli` → 原 `claude_code_harness.native_runner` → gVisor → Claude Code 2.1.160 | `anthropic-messages` |
| `codex` | `camact_multi.coordinator` → gVisor → Codex CLI 0.147.0 `exec` / `exec resume` | `openai-responses` |
| `opencode` | `camact_multi.coordinator` → gVisor → OpenCode 2.0.32 `run --standalone` / `--session` | Chat、Responses 或 Anthropic |
| `deepseek` / `dsh` | `camact_multi.coordinator` → gVisor → dsh 0.2.1-rc.2 `headless` / `--session-id` | `deepseek-messages`，含原有 Files 接口 |
| `openclaw` | `camact_multi.coordinator` → 私有 tmpfs HOME → gVisor → OpenClaw 2026.6.11 `agent --local`、固定 Session ID | Chat、Responses 或 Anthropic |

Canonical Baseline 保留 Python Agent Loop。其他五套保留官方 CLI 的原生 Agent Loop、文件/搜索/图片/工具能力和各自的原生重试行为。这里的 shell 工具不负责替模型规划或选图。

Native Agent 只能获得当前任务的公开工作区、相册/Personal Memory 的允许别名、该 CLI 运行库及任务内 Relay；不挂载完整 Benchmark、GT、真实凭据或其他 User 数据。业务操作仍经 `.camact/adapter.py` → Unix 传输 → 同一 `RuntimeEnvironment` → 每 Session 的独立 Mock 服务。Agent 端模型 Key 是占位值，真实 Key 由可信侧 Relay 注入。

公共 CamAct 任务规则仍由 `benchmark/benchmark_runner/system_prompt.py` 统一生成；官方原生身份和工具协议保留，公共规则在真实请求边界追加。多轮和 History 继续使用现有 Episode/Simulator 实现，续轮绑定具体原生 Session ID，不能改成全局 `--last`。

## 三个模型角色

每个角色分别配置 `*_MODEL`、`*_BASE_URL`、`*_API_KEY_FILE`、`*_PROTOCOL`，前缀为 `AGENT`、`JUDGE`、`SIMULATOR`。Key 文件只在容器启动时读取到内存；运行快照只记 `api_key_env` 名称，所有凭据均来自外部注入。也支持明确注入 `*_API_KEY` 环境变量。

`AGENT_PROTOCOL` 留空时按上表选择默认值：Baseline Chat、Claude Anthropic、Codex Responses、dsh DeepSeek Messages、OpenCode/OpenClaw Anthropic。单个网关若同时支持这些协议，可共享 Agent 模型/URL/Key。只支持 Chat 的端点不能运行全部六套。

每套 Harness 可覆盖 `AGENT_MODEL_CODEX`、`AGENT_BASE_URL_CODEX`、`AGENT_PROTOCOL_CODEX`、`AGENT_API_KEY_FILE_CODEX` 等；后缀使用内部名称大写：`BASELINE`、`CLAUDE`、`CODEX`、`OPENCODE`、`DEEPSEEK`、`OPENCLAW`。如果统一设置 `AGENT_PROTOCOL=openai-chat` 而选择 Codex，启动检查会拒绝该组合。

Judge 和 Simulator 的现有实现只支持 `openai-chat`，其 `*_PARAMETERS` 只接受空 JSON 或 `{"temperature":0}`；不通过修改协议名称冒充其他协议。三者可以使用不同模型、端点和 Key。可选参数：

| 配置 | 默认与限制 |
|---|---|
| `*_TIMEOUT_SECONDS` | Agent/Simulator 600、Judge 120 |
| `*_MAX_OUTPUT_TOKENS` | Agent 2048、Judge/Simulator 8192；与当前正式配置一致 |
| `*_PARAMETERS` | JSON 对象；仅接受原适配器实际支持的参数。Claude Agent 不支持任意参数覆盖 |
| `*_MODEL_OPTIONS` | JSON 对象；用于 OpenCode/OpenClaw/dsh 的原生模型能力声明，可按 Harness 后缀覆盖 |
| `*_RETRY_ATTEMPTS` | Judge 3、Simulator/Baseline/Claude 4；其余四套的模型重试由官方 CLI 控制 |
| `CAMACT_TASK_TIMEOUT_SECONDS` | 原任务外层超时 1800 秒 |

默认 Agent 上限仍为 50 Turn，Simulator 上限 10 Round。当前角色调用上限与评分规则是不同层面的设置，不会修改评分维度或权重。记录的模型配置 SHA-256 不包含 Key，因此允许在保持模型设置不变的情况下更换 Key 文件内容。

全局 `AGENT_RETRY_ATTEMPTS` 只配置 Baseline 和 Claude 的现有适配器；给 Codex/OpenCode/dsh/OpenClaw 明确设置带 Harness 后缀的重试覆盖会在启动检查时拒绝。

## 评分、图片证据和 Usage

六套最终都导出 `StandardRunArtifact` → External Adapter → Python 3.13 Unified Evaluator → `result.json`，保留 Atomic Check、Score、Strict 和基础设施失败分类。Task 本地 `grader.py` 由 `benchmark/evaluator/contracts.py` 动态加载；完整 HF 下载不能只保留静态引用的数据文件。

图片评分还依赖 `evaluation/camact_eval/*.cjs`、`native_codecs.json`、固定 Node/CLI 和编译/提取的图像重放组件。镜像构建时安装官方 CLI 并构建这些组件，启动检查验证对应版本和 SHA-256。不能省略这些库后仍声称图片执行证据完整。

Usage Collector 区分物理 HTTP Attempt、逻辑请求、Agent/Simulator/Judge 与不同执行 Attempt；正式聚合保留缺失字段为 `N/A`，不补成零，不用 Turn/Step 数推算模型请求数。每任务的原始证据、`token_usage/accounting_v3/` 和最终结果仍保留原结构。

## 持久化调度与恢复

`release.runner` 选择 Harness 和 User 后生成新运行目录，调用从现有 `deployment/full_benchmark.py` 保留的单任务命令、结果检查及 `launch/worker/reconcile` 生命周期。User 按固定顺序执行，当前 User 内按 Harness 轮流补充，`--parallel` 是总 Task 并发上限（1–36）。不复用原服务器任何历史评分。

首次创建运行必须使用新的 Run ID。每次调度先持久化 `spec.json` 与 Attempt 预留记录，再启动付费子进程；目录独占创建、`scheduler.lock` 和每 Attempt 的 `worker.lock` 防止覆盖或重复启动。配置文件、源码 SHA-256、Benchmark 仓库/Commit/路径、镜像身份和 CLI 版本写入运行清单，恢复时校验。

`resume` 的具体规则：

1. 已确认有效评分（包括正常 Agent Failure）直接保留，不重复执行。
2. 通过 PID、进程起始 Tick、Boot ID、锁与精确任务标记发现仍活跃的进程时继续等待。
3. 子进程身份不确定时停止派发并保留证据；不通过超时推定已经停止。
4. 已中断且没有有效结果的执行保留为基础设施异常，不自动重放未知付费工作。
5. 默认基础设施 Attempt 上限为 1。明确设置 `--infrastructure-attempts 2` 或 `3` 才允许原调度器对已终结的基础设施失败有限重试；可用的冻结 Agent 证据继续走原有 Judge-only 路径。
6. 配置或源码改变时拒绝恢复。升级镜像或切换 Benchmark Commit 应创建新 Run ID，旧运行用原镜像恢复。

下载器在开始前对指定 Commit 的完整本地文件清单逐个校验；父调度器和存活的 Worker 持有共享版本锁，下载/修复同一版本需要独占锁。运行不会自动切换 Commit。Docker 容器重建会保留挂载的 Benchmark 和结果；容器终止可能同时停止其中的 Worker，恢复仍按以上证据规则处理。

`status` 读取持久化清单；`logs` 读取脱敏的调度事件。`final_report.md` 和 `aggregate/` 是派生报告；最终单任务评分以保存的 `result.json` 及对应证据为准。

## 验证边界

`tests/` 和原 Usage 测试覆盖合成任务、真实 Mock/Relay 通道、Episode、评分与统计合同；无外部模型调用。带 History/多轮的本地协议测试与 CLI 版本/帮助启动检查均不能替代真实模型端到端测评。正式 Benchmark 任务、付费真实模型或完整六套真实 Agent Loop 是否验证，应以本次验证报告中的实际结果为准。
