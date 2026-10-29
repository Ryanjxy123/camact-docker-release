# CamAct 正式 Docker 部署预检

日期：2026-10-29（Asia/Shanghai）。类型：部署审查、完整成功修复同步及验证。方法：`camact-docker-v1`。正式项目为 Git 远端 `Ryanjxy123/camact-docker-release` 对应的服务器 `camact-docker-release/`；相邻 `camact/` 是上游源码与历史产物，不是本次新建的 Demo。两个旧诊断 worktree 保持原样，下一次手动 Actions 使用正式 `main`。

归档根：`harness/_log/2026-10-29/camact-docker-v1-production-preflight/`。所有本轮报告与执行证据直接写入此目录；权限敏感测试在私有 Linux overlay 副本执行，原样迁回 `runs/`，原始路径与逐文件完整性结果留在对应执行清单。没有将大型 raw run 纳入 Git。

开始提交：`3c613d50c9e868b298bedb31cad173bc475ef680`。同步成功提交：`b0592d2f7002d0bd3a2c1e29e02e07e4e35eed85`，共 12 个提交、32 个文件；保留其具名 enforce AppArmor、兼容 Compose 创建、UID/capability 策略、非特权 READY/RELEASE、镜像来源/扫描、完整 HF 与恢复门禁。最终提交和 push 的完整 SHA 由本地 `manifest/delivery.json` 与 Git 记录确认，不将报告中的历史成功状态视为新镜像的验收结论。

文件地图：

- [主报告](report/audit.md)：实际问题、修复、版本兼容边界、验证及手动触发顺序。
- [审查清单](manifest/audit.json)：范围、禁止动作、保护项、测试与未验证项。
- [参考证据摘要](evaluation/reference-summary.json)：四份真实 Artifact 的官方/下载 SHA-256、通过项、两套 CLI 检查及来源限制。
- [本地验证摘要](evaluation/local-summary.json)：完整离线回归、Host gVisor、Native 实际执行及保留产物复核的范围与原件位置。
- [安全审查](evaluation/security-audit.md)：严格 plan 分类、策略检查、镜像 critical digest 的修改与增量回归。
- [最终独立复核](evaluation/diff-review-final.json)：15 份成功产物兼容、缺字段及策略漂移反例、受控非零退出语义。
- `runs/`：真实 API/Artifact、两组 CLI、原始本地回归、Host gVisor 与 Native 合成结果；全部留在本机，不提交。
- [索引](../../EXPERIMENT_INDEX.md)。

未修改 Canonical Benchmark、Task、GT/Rubric、Simulator、Baseline、Unified Evaluator、六套 Harness 核心决策或依赖锁。仅使用合成任务及本地协议服务；正式 Benchmark 执行、付费模型调用、Actions 触发、GHCR 发布均为零。凭据扫描与 `ROOT_ARTIFACT_LEAK` 的最终结果记录在主报告和审查清单。
