# Harness 审查与实验归档

每次审查或验证使用独立的 `YYYY-MM-DD/camact-<method>-vN-<scope>/`，日期按 Asia/Shanghai。入口 README 记录日期、类型、源码、原始位置、方法、主要文件，以及是否修改 Benchmark、评分和执行语义。

`report/` 保存审查报告，`manifest/` 保存复现信息，`evaluation/` 保存精简结果，`runs/` 保存未经重写的原始执行证据。原始位置迁移时保留原件摘要与映射，不覆盖历史运行。

本发布仓库默认忽略整个 `_log/`；仅将已审查、无凭据和个人路径的入口、索引、报告及精简清单显式纳入 Git。大型日志、原始请求、轨迹、数据、工具和缓存不提交，也不进入 Docker 上下文。归档前扫描凭据，结束前检查项目根目录产物泄漏。

所有已登记审查见 [EXPERIMENT_INDEX.md](EXPERIMENT_INDEX.md)。
