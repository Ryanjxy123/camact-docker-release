# Docker stop / kill 恢复验收

本门禁使用原 `release.runner`、`deployment.full_benchmark` 的 scheduler、launch、worker、reconcile、结果检查、Codex CLI、gVisor 和正式 Evaluator。没有 monkeypatch 或替代终止/评分协议；全部任务、32×32 图片、grader 和模型响应都是本次独立合成夹具。没有真实 Benchmark、HF 下载、付费模型、GHCR 发布或真实用户数据。

先在同一源码 SHA 运行 `publish.yml`，要求 `version=0.1.0-rc.1`、`publish=false` 成功，随后手动触发 `verify-recovery.yml`：

```text
image_run_id=<成功的 publish.yml Run ID>
expected_source_revision=<与当前 workflow HEAD 相同的完整 SHA>
version=0.1.0-rc.1
```

门禁复用完整缓存验收的正式 Run、源码、artifact 五字段、归档 SHA-256、OCI 版本及完整镜像逐层扫描检查。扫描成功前零容器启动。全部容器固定同一不可变 image ID；Runner 只有一个私有 `/var/lib/camact` bind、network=none、UID/GID 10001、capabilities 全零、NNP、正式 seccomp/AppArmor、只读根目录、pids=4096 和原三项 tmpfs。宿主和容器内实际 policy/mount 握手通过后才放行。Installer 只增加固定合成缓存 `fixture/recovery`、40 个零 Commit 的 alias 目标，Memory mount source 仍是任务 workspace/album。

原 `camact_multi.fixture.create` 在私有 cache snapshot 内生成三个不同 Task ID。生产 cache manifest/ensure 创建合成完成标记；所有入口传 `--offline`。三个模型角色使用固定 loopback 端口和固定合成配置，Agent 只接收与 `native-loop-smoke.py` 相同的确定性 Responses 工具动作与响应 helper。

`stop` 和 `kill` 各使用独立 Run ID、Codex、parallel=1、infrastructure-attempts=1：

1. 原 Runner 执行 A，真实评分成功后进入 B；B 原 worker/child 身份已发布、worker 锁仍持有，首个真实 fixture 请求保持阻塞，C 尚未预留 Attempt。
2. 宿主记录 Docker 内全部宿主 PID/start_ticks/boot_id，并分别调用 `docker stop --time 60` 与 `docker kill --signal KILL`。要求 stop 退出 3、kill 退出 137；旧进程身份必须全部消失。删除原容器。
3. 新容器先只读观察原锁、namespace PID 身份、源码/配置/镜像/Benchmark/CLI 冻结信息和原请求计数，要求无旧活跃执行、无新增派发。
4. 再新建容器调用原 `release.runner resume`。A 的评分、产物摘要、Attempt 和物理请求计数不变；B 成为 infrastructure_error 且不重放；C 真实执行并评分成功。再次创建容器重复原 resume，要求所有任务产物、计数和 Attempt 完全不变。

正确的原运行结局为 `finished_with_infrastructure_errors`、退出码 **3**，因为 B 被真实中断且无有效评分。验收脚本只在精确符合这一原语义时返回成功，不将该 Run 改成 complete 或把 B 伪造为通过。

正常完成的 A/C 必须保存真实 gVisor 执行和退出/清理证据。被 SIGKILL 的 B 可能缺 lifecycle.json、保留磁盘状态目录；报告明确给出缺失计数和保留目录的不可逆摘要，不删除后宣称清理完成。进程/锁清理与磁盘遗留分别记录；本门禁不证明强杀时 Python finally 一定执行。实际超时、身份不确定、版本改变、重复请求、缺评分或工具/图片证据不足均 FAIL。

云端归档位于 `harness/_log/<Asia-Shanghai 日期>/camact-docker-recovery-v1-<run-id>-<attempt>/`。仅上传 README、验收 manifest、report、summary，以及 Workflow 最后补充的独立 `cleanup.json`；私有 cache、相册、task/grader、原始请求体和模型/执行日志不上传。公开内容为固定检查项、原进程身份、版本、计数和摘要；不包含真实数据。所有容器带本轮双 label；always 清理只作用本轮，发现意外残留即保持 FAIL，无任何容器引用后才卸载临时 Runner 的 profile，不执行全局 prune。主 report 的 PASS 不覆盖最终 cleanup 失败，最终以全部文件和 job 结果共同判定。

离线单测与 Docker mock 只证明验收脚本合同。真实 stop/kill/resume 是否通过，必须查看本轮实际 Actions 的两组完整证据，不能用 mock 结果替代。
