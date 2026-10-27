# 固定原生运行时与隔离边界

本发布使用正式配置指定的包，而非当前登录 shell 的同名全局命令。

| 组件 | 固定版本 | 发布镜像中的位置 / 安装来源 |
|---|---|---|
| Node.js | 24.14.0 | `/opt/camact/.tools/node/bin/node`，官方 nodejs.org 压缩包及 SHA256 |
| gVisor | release-20261012.0 | `/opt/camact/.tools/gvisor/20261012.0/runsc`，官方 gvisor.tar.bz2 及 SHA512，保留全部 gvisor-bin sidecar |
| Claude Code | 2.1.160 | `.tools/claude/node_modules/.bin/claude`，`@anthropic-ai/claude-code` |
| Codex CLI | 0.147.0 | `.tools/codex/node_modules/.bin/codex`，`@openai/codex` |
| OpenCode | 2.0.32 | `.tools/opencode/node_modules/.bin/opencode`，`@opencode/cli` |
| DeepSeek Harness | 0.2.1-rc.2 | `.tools/deepseek/node_modules/.bin/dsh`，`@deepseek-ai/dsh`；上游预发行版 |
| OpenClaw | 2026.6.11 (e085fa1) | `.tools/openclaw/node_modules/.bin/openclaw`，`openclaw` |
| Rust（仅构建评分辅助程序） | 1.90.0 | Docker 构建阶段；不放入最终运行镜像 |
| ripgrep | 13.0.0（Debian `13.0.0-4+b2`） | 最终镜像 `/usr/bin/rg`，由 Debian 官方 apt 安装；包校验见 `locks/system-tools.json` |

`locks/runtimes.json` 固定运行时下载地址与校验值；`locks/cli/<name>/package-lock.json`
保留实际已验证安装的完整 npm 依赖闭包，全部 resolved 地址均为公开 npm registry。
安装通过 `bash scripts/install-runtimes.sh`，对五套官方包分别执行 `npm ci --prefix`；
不复制旧服务器上的安装目录。独立空 npm 配置和专用 cache 避免读取个人配置。

OpenCode 原生 grep 优先使用 PATH 的 `rg`，否则尝试联网下载；每任务沙箱禁网，
因此镜像明确安装固定 ripgrep。该版本支持当前 OpenCode 使用的全部搜索参数。
这是部署复核发现并补入的依赖，不把宿主 shell 的其他 rg 路径视为原沙箱依赖。
dsh、Codex、Claude 的已选安装包另带自己的搜索实现；git 不是当前 Task 执行的启动依赖。

镜像内可执行 `python scripts/check-runtimes.py` 检查实际 CLI、Node、runsc 和
评分图片编码器的文件校验；`--sandbox` 进一步让五套 CLI 在生产 gVisor 构建器中
各运行一次 `--version`，并检查退出、`runsc delete --force` 和状态目录清理。
这些版本检查不调用模型。

`scripts/native-loop-smoke.py` 可进一步运行原生 CLI 的完整合成流程，例如：

```bash
python -B scripts/native-loop-smoke.py --harness codex --mode multi_turn \
  --output /var/lib/camact/validation/native-codex-multi-001
```

`--harness` 支持五个官方 CLI，`--mode` 支持 `single_turn`、`multi_turn`、`users_history`。
每次必须使用全新输出目录。该脚本创建合成 Task、相册与本地确定性协议服务，不读取
正式 Benchmark、不调用真实模型；实际运行官方 CLI、原 gVisor、原生读图/终端工具、
业务 Mock、Simulator 续轮及 STOP、Unified Evaluator、Atomic/Strict 和用量汇总。
验收同时检查原生工具返回的只读资源/历史/非法业务动作断言、图像证据、每角色请求
计数与精确 Token 总数；完整请求及运行产物保存在指定目录。宿主直接运行成功仍不代表
Docker 集成通过。

## 执行关系

Baseline 继续使用原 Python Agent Loop。Claude 委托原 `claude_code_harness.native_runner`；
其余四套由 `camact_multi.coordinator` 创建独立 Task Runtime 后，经 `drivers.prepare`
生成原生配置与启动参数。`drivers.resume_command` 使用本次任务原生 Session ID 续轮，
不会选择其他任务的 last Session。通用 Prompt 仍在原请求边界追加，工具与 Agent Loop
仍由各官方 CLI 提供。

Docker 内的可信调度器、业务 Mock、Simulator、Judge、评分器和 Relay 保持原调用关系。
每次 CLI 调用使用原 rootless gVisor OCI/Systrap 边界：单 UID/GID user namespace、
空 capabilities、noNewPrivileges、network=none、Sentry 提供的 procfs。
只挂载只读系统运行库、只读固定 CLI/Node 包、当前任务 workspace/HOME、
当前用户相册副本和原 Personal Memory 同源只读别名。原 Benchmark、GT、其他用户目录、
真实凭据文件和 Docker socket 不进入 Agent 文件视图。

CLI 使用占位 Key 访问沙箱内 loopback HTTP launcher；launcher 只经当前任务的
Unix socket 访问可信 Relay 和业务 Adapter。真实 Key 在可信侧按既有协议注入。
因此业务 Mock/Relay 无需向 Agent 开放 Docker 网桥或宿主 TCP 端口。

发布副本还限制了原 OpenClaw 权限预检的环境变量：该可信 Python 探针只接收最小
PATH/locale/Python 设置。gVisor 在写入显式 Launch Plan 以及合并进程环境后，均移除
`AGENT_API_KEY*`、`JUDGE_API_KEY*`、`SIMULATOR_API_KEY*`、Hugging Face Token 和
原 `CAMACT_ZCLOUD_API_KEY`。官方 CLI 需要的原占位 Key 仍由各 driver 提供。
`check-runtimes.py --sandbox` 会注入十种合成 canary，验证其未进入 Guest、Launch Plan、
生命周期日志并验证状态清理；不会读取或输出部署账号的真实凭据。

本封装将 runsc 与 CLI 安装在同一镜像中，由非 root Docker Runner 创建每任务 rootless
gVisor；不运行 Docker daemon，不挂载 Docker socket，不使用 privileged。
`deploy/seccomp-gvisor.json` 保留 Docker 标准默认拒绝规则，只显式允许 namespace、mount
和 Systrap 所需调用；内核的 namespace/capability 检查继续生效。实际 Docker 集成是否
通过，以验收报告为准；宿主直接运行 gVisor 的成功不能替代 Docker 内验证。

OpenClaw 保留原 ext4/tmpfs 门禁、私有 HOME、0600/0700、Session 增量采集、文件锁和
归档字节校验。Compose 提供独立、私有、当前 UID 所有的 256 MiB tmpfs；配置
`CAMACT_OPENCLAW_TMPDIR=/run/camact/openclaw` 后，原门禁可直接验证该真实挂载。
未提供兼容挂载时，原 private_tmpfs steward 仍保留；不能移除检查来放行 overlay/NFS。

各 CLI 仍使用其原生模型能力配置；图像模型必须在对应目录中声明图像输入能力。
例如 dsh 的自定义模型可设置：

```dotenv
AGENT_MODEL_OPTIONS_DEEPSEEK='{"inputModalities":["text","image"],"contextWindow":1048576,"maxTokens":2048}'
```

该值传入原 dsh provider catalog，不改写模型请求、原生工具或图片编码行为。

## 图片证据与构建

评分器动态使用 `evaluation/camact_eval/native_codecs.json` 指定的原生编码器和 SHA256。
`scripts/build-codecs.py` 从固定 Claude CLI 原始字节提取其未修改的 N-API 图片模块，
用 Rust 1.90.0 和原 Cargo.lock 构建 Codex 图片重放辅助程序；保留 OpenCode 内嵌
Photon WASM 与对应 npm 模块的字节一致性检查。构建仅更新生成辅助程序的实现指纹，
不改变评分器、图片证明、Atomic Check 或权重规则。Sharp、rastermill 由固定 npm
依赖树提供，保持原项目布局，不能仅安装可执行单文件而省略包资源。

`python scripts/check-codecs.py` 使用新建合成图片检查三套编码器的实际 resize、完整
编码字节 SHA 重放和错误 SHA 拒绝。它不读取 Benchmark，不调用模型，不代表测评成绩。

部署需要独立宿主账号。多个人共用同一个 Linux UID 时，0600 文件不能在这些人之间
隔离凭据；运行结果目录、Docker 管理权限和密钥管理权限应只属于部署账号。
