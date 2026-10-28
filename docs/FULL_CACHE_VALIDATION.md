# 最终镜像中的完整 HF 缓存验收

这是显式触发的数据完整性验收，不启动正式 Task、Guest、Agent、Judge 或 Simulator，不调用模型。它不会发布 GHCR，也不把数据集写入镜像。

先让同一源码 SHA 的 `publish.yml` 以 `version=0.1.0-rc.1`、`publish=false` 成功完成全部正式集成门禁，并生成保留 3 天的 `camact-verified-image` artifact。然后在相同源码 SHA 上手动触发 `verify-full-cache.yml`，提供：

```text
image_run_id=<成功的 publish.yml Run ID>
expected_source_revision=<与当前 workflow checkout 相同的完整 Git SHA>
version=0.1.0-rc.1
```

Workflow 只接受本仓库成功的 `workflow_dispatch` / `publish.yml` 运行；其 HEAD、输入 SHA、当前 checkout 和镜像 manifest 源码版本必须一致。它校验镜像归档 SHA-256、不可变 image ID、OCI/环境版本，然后对加载后的完整镜像重新逐层扫描。扫描失败时不能创建存储 helper 或 Runner。所有容器固定使用该 image ID。

实际数据验证只调用原 `release.benchmark.ensure/lease`：

1. 第一容器只在可信外层使用 Docker bridge 网络，从官方 HF 下载 `Ryanjxy/CamAct-Benchmark` 的固定 Commit `53e2f450042485dfc4a3b566de6f46988c3a5661`。原下载器确认远端 resolved SHA、完整文件清单、每文件大小、Git blob SHA-1 或 LFS SHA-256，全部成功后才生成完成标记。无个人 HOME、隐式 HF token 或模型 secret 注入；当前入口仅支持匿名下载。
2. 删除第一容器，从同一 image ID 和私有持久目录创建 `network=none` 的第二容器。两次 `ensure(offline=True)` 和完整 `lease(offline=True)` 重新验证本地内容；所有网络、HF API/下载、HTTP client、凭据入口都设为一旦调用就失败，并要求调用计数为零。共享 lease 期间独占锁必须被阻止，第二共享读取必须成功，lease 退出后独占锁才能获得。
3. 删除第二容器并再次创建独立 `network=none` 容器，重复上述检查。三容器的文件数、字节数、manifest 摘要和 marker 摘要必须完全一致。

三轮还会在原 shared lease 内，从已完成哈希校验的 manifest 路径集识别全部 `tasks/U/task_*/task.yaml` 调度入口，逐个要求对应 Memory manifest，不能因缺失文件而漏掉 Task。这里只读取 `memory_manifest.json.runtime_root`，不解析 Task YAML、GT、grader 或图片。解析保持原 `raw_root` 语义：相对路径 resolve，绝对路径保留原 Path 字符串；最终必须精确等于当前快照的 `users/U/base_memory`，且目标为普通目录。旧宿主路径、跨用户/版本、绝对路径中的 `..`、双斜杠及软链接都会失败，不会扩展 AppArmor 来容纳错误布局。公开报告仅给出 Task/用户/绝对与相对根的数量和匹配布尔值；三轮聚合必须一致，不输出用户标识、原路径或字段内容。

下载与离线容器保持正式 Compose 的 UID/GID 10001、五组 capabilities 全零、只读根目录、NNP、仓库 seccomp、`camact-gvisor-v1 (enforce)`、pids=4096 和三项 tmpfs。禁止挂载模型 secret；唯一持久 bind 为本次私有 `/var/lib/camact`。每个 Runner 先等待握手，宿主验证创建前后的实际 Docker security/mount，容器内复用 `verify-runner-policy.py` 的真实 `/proc` 与文件系统观察，全部通过才放行数据操作。存储 helper 使用原有 CHOWN/DAC_OVERRIDE/FOWNER 组合、只读根目录和 network=none。

匿名限速为每秒最多 2.5 文件。历史清单为 22,121 文件，排队下限约 147 分钟，还需元数据、传输、哈希与退避时间；240 分钟 job 不保证任何网络环境都能完成。现有下载器只做有界重试，遵守 Retry-After。401/403/404、磁盘不足、超时、下载不完整、缺标记或哈希不符均记录真实 FAIL；部分下载不构成完成证据。需要认证时应先安排明确授权的只读 HF secret 流程，不能回退读取个人凭据。最低宿主资源为 2 CPU、4 GiB 内存和 16 GiB 可用磁盘；不通过删除宿主缓存来绕过资源检查。

同一 job 的三容器共享私有 bind，不使用 Actions cache/artifact 跨 job 保存数据集。云端目录为：

```text
harness/_log/<Asia-Shanghai 日期>/camact-full-cache-v1-<run-id>-<attempt>/
  README.md
  manifest.json
  report.json
  summary.json
  cleanup.json             # workflow 独立清理结果，不重写主报告
  private/                 # 禁止上传；runner 生命周期结束时丢弃
```

artifact 严格限定上述入口文件，仅包含版本、数量、总字节、整体摘要、固定检查项和调用/锁结果。完整 HF 文件清单、用户名称、GT、照片、原始日志及缓存不会上传、进入 Git、镜像或 registry。`manifest.json` 是验收产物索引，不是数据集文件清单。下载失败也不将原始异常、signed URL 或任意文件名写入公开报告。

本门禁不验证正式 Benchmark 成绩、付费模型行为或 Docker stop/resume；现有 `verify-docker.sh` 的合成单文件缓存和持久化 marker 也不能替代本次全量验收。通过状态只能以本轮实际 `report.json` 和三容器证据为准。
