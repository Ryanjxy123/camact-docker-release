# 发布验收记录

验收日期：2026-10-28。镜像发布结论：**NOT_READY_TO_PUBLISH**，等待本轮修复后的完整 Docker Actions 验收。

## Run #4 whiteout 修复与发布前预检（本轮）

失败记录为 [Run #4 / `40696049225`](https://github.com/Ryanjxy123/camact-docker-release/actions/runs/40696049225)，源码为 `1d7b69ed9769b93c99ec96635dd5b941fdb6490e`。真实诊断中恰有 15 条 `personal_config_or_credential_path`，全部位于 `layer[4]:etc/ssl/certs/.wh.<CA 名称>.pem`；构建、151 项离线测试和依赖/运行时检查已经通过，GHCR 步骤跳过。

15 条命中指纹均等于路径的 SHA-256，结合旧代码可确认它们经过了常规文件扫描分支，被 `.pem` 路径规则误判。固定 Python 基础镜像内的 CA 包为 `20230311+deb12u1`；核对 SHA-256 认证的官方 Debian `ca-certificates_20250419~deb12u2_all.deb`，升级删除的证书与这 15 个名称逐一对应。原 Artifact 没有保存镜像层 tar 或成员头，**不能直接恢复原始标记的确切大小或 regular typeflag**；新扫描器会对实际输入逐项验证，绝不因名称相似就放行。

按 [OCI image-spec v1.1.1 层规范](https://github.com/opencontainers/image-spec/blob/v1.1.1/layer.md#whiteouts) 接受空的常规文件删除标记和精确的 `.wh..wh..opq` opaque 标记；拒绝空目标、`.`/`..`、异常保留名称、whiteout 祖先路径、非空内容、链接、目录、设备、稀疏文件及异常设备/链接元数据。原生 overlayfs 字符设备不是 OCI tar whiteout，不予接受。标记名称仍扫描凭据，所有历史层中的真实敏感内容仍扫描；没有豁免证书目录、所有 PEM 或依赖目录，也没有修改上游例外锁。

另外通过独立探针确认并修复以下实际问题：

- CA 目标被删除、被链接替换或其父目录被链接替换后，旧扫描器仍保留公共证书信任，可能错误批准新 PEM 链接。现在逐层结算 CA 状态、在本层验证链接，whiteout 仅影响下层证书，同层重新添加证书与 tar 顺序无关；历史合法链接不会被后层删除追溯误报。
- 本地 `camactctl build` 会在扫描前执行存储初始化容器；验收还会挂载调用者的真实配置、Secrets 和数据。现在保留构建参数/源码版本标签，直接构建候选，然后先检查身份并扫描不可变镜像 ID，安全通过后才执行容器；测试使用独立合成配置、占位凭据、存储和 Compose 网络。原有 `--network=none` 离线/运行时检查完整保留并移到扫描后。
- 验收原先在首个失败后结束，隐藏独立故障。现在收集独立门禁的结果，对依赖失败明确记录 SKIP；任一必需门禁未 PASS 都整体失败。每阶段在独立的严格 errexit 上下文执行，避免收集状态时吞掉函数内错误；项目清理本身也是严格门禁。
- 发布原先重新引用可变标签。现在扫描、容器执行和最终发布均使用同一不可变 ID，只有所有门禁通过才输出发布候选。Workflow 仍只手动触发，`publish=false` 不登录或推送 GHCR。

失败输出包含阶段、退出码、固定错误分类及依赖状态。Artifact 白名单仅含脱敏的镜像扫描、阶段汇总和 AppArmor/seccomp/子 user+mount namespace 诊断 JSON；原始日志、inspect、调用者配置、凭据及缓存保留在私有目录，不上传。没有为收集诊断而允许未扫描通过的镜像接触真实凭据。

| 检查 | 本轮结果与边界 |
|---|---|
| 完整离线回归 | Python 3.13.11；原 151 项全部保留，新增 4 项扫描和 6 项 Shell 回归后 **161 项通过，零失败/错误/跳过**；其中扫描 27 项、Shell 协议 stub 8 项。stub 不代表真实容器通过 |
| 本次故障复现 | 4 个 SHA-256 认证的官方 Python 基础层，加同名 15 个常规零字节 whiteout 的重建归档：旧扫描器准确复现全部 15 条，修复后扫描 5,050 文件、120,426,789 字节，通过 15 个 whiteout、143 个公共 CA 路径；这是重建证据，不是恢复的 Run #4 镜像 |
| 归档与官方依赖兼容 | 原有 Docker/OCI、压缩层、Moby 遗留配置、精确依赖例外和历史层回归全部保留；固定官方基础层再次扫描通过，未扩大例外 |
| Compose 与 UID | 官方 Compose 2.40.3 实际配置解析、合成配置和带空格路径通过；生产初始化代码在隔离 user/mount namespace 的私有 tmpfs/chroot 中实测 UID 10001 可写六类数据目录，Secrets 为 0400、目录 0711，重新初始化不截断内容；不是 Docker 实际挂载验收 |
| 后续入口与宿主运行时 | HF/Runner/camactctl/Baseline 合成流水线 33 项定向检查通过；固定运行时版本、15 个 codec 摘要、五套宿主 gVisor 生命周期和十种凭据 canary 通过；不是容器内六套 Harness 验收 |
| 完整 HF 宿主缓存 | 固定 Commit 的 22,121 文件、2,350,271,484 字节，经生产 `ensure(offline=True)` 和 lease 两轮全量哈希复用通过，外部调用为零；未下载、未运行任务，不代表容器缓存/恢复通过 |
| 静态与安全检查 | Shell 语法、两个 Workflow 的 actionlint、追踪源码安全扫描及 diff 检查通过；受保护源码、Dockerfile、Compose、依赖锁和全部核心测评行为保持不变 |

当前仍为 **NOT_READY_TO_PUBLISH**。真实最终镜像逐层扫描、Docker 绑定挂载/UID/Secrets/重建生命周期、容器内 gVisor、Baseline 与五套 CLI 的 15 项矩阵、完整 HF 容器缓存及 Docker 终止/恢复仍须目标主机验收。本机外层隔离限制见下文，未声称这些检查通过。另已核实 Docker 默认 AppArmor profile 含 `deny mount,`，现有 Compose 没有经验证的替代策略；这是嵌套 runsc 的明确宿主策略风险，新增诊断可定位，但本轮未猜测性放宽 AppArmor、seccomp、namespace、capabilities 或非 root 限制。

本轮仅修改扫描器、两份回归测试、必要验收脚本/Workflow 和本文档，共六个文件。证据在本地忽略目录 `.validation/run4-preflight/` 与 `.validation/run4-gates-config/`，不入 Git 或镜像。可以在推送后的 main 手动用 `version=0.1.0-rc.1`、`publish=false` 重跑；本轮不触发 Actions、不发布 GHCR、不运行正式 Benchmark、不调用付费模型。

## Run #3 镜像归档清单修复（历史）

失败记录为 [Run #3 / `40679929807`](https://github.com/Ryanjxy123/camact-docker-release/actions/runs/40679929807)，源码为 `020c4417ca9695c6333366e1e2a7ef0940c2ae2b`。实际诊断 artifact 确认：扫描已读取 106,300 个文件、3,299,979,110 字节，随后以 `ScanFailure: undeclared_image_layer` 失败，阶段为 `image-security-scan`。构建、146 项离线测试和运行时检查成功，GHCR 步骤跳过。原始 `docker save` 归档及集合差集没有保留，因此不能恢复该次运行中额外 Blob 的具体名称和数量。

核对 [Moby v28.5.1 官方导出器](https://github.com/moby/moby/blob/v28.5.1/image/tarexport/save.go) 后，确认 `saveImage` / `saveConfigAndLayer` / `saveConfig` 会为每层写出兼容旧版 Docker 的 V1 配置 JSON，存入 `blobs/sha256/<内容摘要>`。这些配置不在 Docker `manifest.json` 的 Config/Layers 或 OCI descriptor 引用集合中。原校验将所有剩余 Blob 都计为层，因此合法 V1 配置进入 `actual - declared`，触发当前错误；这与可达 OCI manifest/index 元数据及真正未引用的层是不同类别。按官方格式构造的同一归档，已验证原源码失败、修复后通过。

另实际调用未经修改的官方 `tarexport.NewTarExporter.Save`，使用内存中的两层合成存储生成归档，独立验证序列化兼容性：清单外恰好有两个 V1 配置 Blob，其他文件分别为声明的镜像配置/层、可达 OCI manifest、index/layout 和 repositories 元数据。UTC、Asia/Shanghai 及 Created 为空的四种组合均验证旧源码失败、修复后通过；本机时区的 Unix 零时刻可表示为 `1970-01-01T08:00:00+08:00`，按实际时刻验证并保留原文参与 ID 校验。这是官方导出器测试，未使用 Docker daemon 或真实容器，也不是 Run #3 原归档。

本轮只修改扫描器、其回归测试及本文档：

- 对额外 Blob 逐一验证 V1 字段、类型和内容 SHA-256，再按 Moby `v1.CreateID` 算法验证配置 ID、父配置和声明的 rootfs DiffID/ChainID，只有完整匹配的层链才认作遗留配置。保留 Go 对嵌套字段顺序、HTML 和 Unicode 的序列化行为。
- 所有接受的 V1 配置同时扫描原始 JSON 和解码内容，转义不能遮蔽凭据；所有声明层、历史层及现有敏感文件/密钥规则继续执行。任意额外 JSON、未引用层/Blob、错误摘要、错误 ID/父链及不完整链继续拒绝，没有扩大例外策略。
- 清单失败保留固定错误码，并增加 `layer-inventory` 阶段、actual/declared 数量、元数据分类和最多十个额外路径的 SHA-256；不输出候选值或未过滤的路径。现有 Shell 阶段诊断和失败阻断保持有效。

验证：使用现有 Python 3.13.11 干净依赖环境，原有 **146 项**全部通过；新增 5 项回归后完整 **151 项**通过，零失败/错误/跳过，其中 **23 项镜像扫描测试**和 **2 项 Shell 门禁测试**通过。新增用例覆盖单层/多层 Moby 格式、历史层和遗留配置中的凭据、脱敏、签名有效但字段异常的配置、断裂层链、损坏摘要、额外 JSON/层/Blob 及有界清单诊断。源码扫描通过。后续入口复核未发现与本问题直接相关、需要修改的其他缺陷。

本轮证据在本地忽略目录 `.validation/run3-layer-inventory/`。未在宿主构建或运行真实 Docker 容器；最终镜像扫描、Compose 实际挂载/UID/Secrets、容器内 gVisor 和六套 Harness（含五套 CLI 的 15 项矩阵）、HF 缓存及跨容器持久化仍需完整 Docker 验收。可以在 main 手动使用 `version=0.1.0-rc.1`、`publish=false` 重跑 Actions；本轮不触发 Actions、不发布 GHCR、不运行正式 Benchmark 或调用付费模型。Dockerfile、运行时/CLI 安装、Compose、Harness 和评分实现均不在修改范围。

## 前次 Actions 故障修复（历史）

失败记录为 Actions Run `40662252249`，对应源码 `cad056266e25db75d609a334cd7ce3af34ece37e`。GitHub API 确认构建、离线测试和运行时检查成功，集成步骤失败；公开 annotation 仅有 `exit code 1`，历史扫描 JSON 未被保留，不能确认历史运行首先命中了哪条规则。

当前源码和固定官方制品已复现以下阻塞，并实施修复：

- `verify-docker.sh` 原先将扫描 JSON 重定向到本地文件，随后由 `set -e` 直接退出。现在使用保留 `pipefail` 的 `tee` 输出脱敏 JSON，并为初始化、扫描、HF 缓存、gVisor、各 Harness/模式及持久化检查报告阶段、行号和退出码。归档/解压错误保留错误类型、固定原因码和位置；不打印候选值或原始 Docker stderr。
- 扫描器原先拒绝官方 Debian 层的 `./` 根目录记录，以及仅含目录/符号链接的合法层。现在接受这些合法结构，继续拒绝路径穿越、缺失/损坏层和未声明层。也支持 Moby/containerd 导出的 OCI blob 布局及压缩层，并扫描其引用的 OCI 元数据。
- 官方 Node 24.14.0 命中公开编译路径和 llhttp Token 常量。重新核对官方 `SHASUMS256.txt`、锁定归档及安装二进制摘要后，扩展核验了 npm、Python wheels 和固定基础镜像中的同类公开源码/文档/编译路径命中。
- `locks/image-scan-exceptions.json` 只批准明确路径、完整文件 SHA-256 和具体命中指纹的组合，并记录公开归档 URL、锁定校验值、归档成员和审查说明。加载时校验来源与当前 Dockerfile/依赖锁一致；变化必须重新审查。所有文件仍读取和扫描，额外文件、内容变化、元数据凭据及未批准命中继续失败。同一路径可记录不同镜像层中分别认证过的版本。
- 公共 CA 的 `.pem` 后缀原先也会被当作凭据路径。现在完整解析纯公共 X.509 证书，并验证标准 CA 符号链接的实际公共证书目标；私有配置目录、无效证书及附加内容仍不能通过。带上游注释头的固定 CA bundle 使用逐文件哈希记录。
- 镜像归档和层内容按块读取，避免同时保存整个镜像及全部层的内存副本。pip 26.2.2 增加独立哈希锁；安装使用 `--no-compile`，避免生成带构建时间的字节码缓存，依赖版本和业务行为保持一致。

Actions 使用 `always()` 保存 `docker-verification-diagnostics` artifact，保留 7 天。文件仅为 `image-security-scan.json` 和 `verification-summary.json`；原始 inspect、日志、配置、凭据、Benchmark 和执行产物不在上传范围内。扫描或集成失败仍会阻止 GHCR 登录和发布。Workflow 仍只有手动入口，普通 Push 不会触发 Actions。

本轮验证结果：

| 检查 | 实际结果与范围 |
|---|---|
| 原有离线测试 | 131 项通过，零失败/错误/跳过 |
| 新环境与完整离线测试 | Python 3.13.11；pip 和 35 个运行依赖按哈希离线安装，`pip check` 通过；146 项测试通过，零失败/错误/跳过 |
| 扫描及 Shell 失败阻断回归 | 18 项扫描测试和 2 项真实 Shell + Docker 协议 stub 测试通过；覆盖错误可见、凭据脱敏、精确例外、真实凭据注入、损坏/遗漏层、压缩 OCI、公共证书及后续 Compose 失败。stub 测试不代表容器测试通过 |
| 运行时与图片 codec | 宿主官方版本检查和 codec 合成检查通过；未将结果解释为容器内 gVisor 通过 |
| 当前安装内容扫描 | 本地合成 tar 覆盖 COPY 源码、官方运行时、干净 Python 安装及 codec，共 100,857 个常规文件、约 3.17 GB，零未批准命中；属于本地内容检查 |
| 固定 Python 基础镜像 | 官方 OCI index、amd64 manifest 和 4 个层分别校验 SHA-256；5,035 个常规文件、约 120 MB 扫描通过，143 个公共证书路径验证通过；未运行容器 |
| 构建上下文与静态检查 | Moby 官方 patternmatcher 确认 195 个 COPY 文件及 35 项排除探针；新增锁、策略和回归测试进入上下文。Shell 语法、actionlint 和源码安全检查通过 |

本轮证据保存在本地忽略目录 `.validation/actions-scan-fix/`。Benchmark、GT、Rubric、Simulator、Baseline、Unified Evaluator 和六套 Harness 核心文件不在修改范围内。没有启动正式 Benchmark、调用付费模型、触发 Actions 或发布 GHCR。

仍需用户手动以 `version=0.1.0-rc.1`、`publish=false` 运行：最终镜像构建与逐层扫描、Compose 挂载和 UID/Secrets 权限、容器内 gVisor 生命周期/凭据边界、Baseline 三类合成测试与五套原生 CLI 的 15 项矩阵、合成 HF 缓存跨容器复用及持久化。完整 HF 下载/离线缓存挂载、Docker 终止/恢复仍是后续发布验收项。若 gVisor 失败，先检查宿主 AppArmor audit 和子 user/mount namespace 支持；本轮未放宽 seccomp、AppArmor、capabilities 或非 root 限制。

## 原发布准备记录（历史）

以下保留本轮修复前的发布准备记录，测试数量、上传状态和阻塞描述采用当时口径；当前结论以本文开头的 Actions 修复记录为准。

发布源码、部署文件、六套 Harness、锁定安装和本地合成执行已准备。当前服务器的外层隔离阻止 Docker 完整镜像构建和普通容器启动，因此尚未满足 `READY_TO_PUBLISH` 的核心 Docker 门禁。宿主 gVisor 测试通过不代表容器内通过。

本轮未上传 GitHub/GHCR、未触发远端 Actions、未启动正式 Benchmark 测评，未调用付费模型。真实 HF 下载仅用于指定版本的本地完整性验证；没有重复远端内容审计。

## GitHub 上传前最终检查

本次检查以当前工作区为准，范围限于上传安全和发布配置，不重构 Harness、Benchmark 或评分逻辑。

- Git 边界：本目录使用独立的实体 `.git`，无共享 objects/alternates、commondir、子模块或远端；正式 `camact` 不在本仓库中。原目录 258 个受保护源码/配置文件的 SHA-256 和 mtime 全部保持一致。
- 源码与历史：205 个原追踪文件扫描通过；两个可达提交中共 209 个文件路径/Blob 组合及提交元数据检查通过，未发现真实 Key、Token、个人配置、敏感项目路径或数据产物。字面凭据候选经复核均为合成测试占位值或源码/依赖名称。Git 历史保留已有作者署名与邮箱归属元数据。
- 排除规则：28 个 Git 忽略探针通过。Moby 官方解析器重新确认构建上下文为 192 个文件，全部来自 Git 追踪文件，无符号链接；35 个数据/缓存/凭据探针均被排除。`benchmark/` 仅包含必需的 Runner、Services、Evaluator 源码及评分注册表，未包含 Tasks、Users、GT 数据目录。最终修改限于 Workflow、验收脚本和本验收文档/README，COPY 文件清单未改变。
- 依赖与入口：35 个 Python 依赖均精确固定且带 wheel SHA-256；五套官方 CLI 的 package.json、package-lock 与运行时版本一致，依赖使用公开 npm registry 并带完整性校验。Baseline 加五套原生 Harness、三角色配置、HF 固定 Commit、持久化挂载与 gVisor 验证入口已复核。镜像和 Compose 面向 `linux/amd64`，Debian 容器用户空间不绑定某一 Ubuntu 宿主版本；宿主仍需满足内核和隔离条件。
- 既有测试：逐文件哈希确认既有 131 项离线测试所覆盖的 Python 实现、测试和依赖锁均未改变；15 项宿主原生合成矩阵、HF 完整下载与离线复用证据已复核。相对 COPY008 唯一的构建上下文变化是下述验收 Shell 脚本，不把旧 COPY 证据解释为该脚本的 Docker 验证结果。本轮没有重跑真实 Benchmark，也没有把宿主结果解释为容器测试通过。
- Actions 必要调整：取消自动 Release 触发，手动 `publish` 默认 false；复用同一套构建/验收步骤，只有显式发布分支获得 `packages: write`。源码扫描前置到构建之前，Checkout 不保留凭据；两个 Workflow 均通过 actionlint 1.7.12。普通 Push、Tag、Release 不触发发布；验证失败不会执行 GHCR 登录或推送。
- 验收脚本必要修复：原合成 HF 缓存由宿主用户创建；当其 UID 不等于 Runner 的 10001 时，0755 仓库目录会阻止 Runner 创建缓存锁，导致云端容器门禁失败。现改为先初始化存储，再由同一 Runner 容器用户创建合成缓存，消除宿主所有权和路径解析差异。Shell 语法检查、脚本实际内嵌 Python 及生产 HF `ensure(offline=True)` 两次复用验证通过，网络/Token 入口均用失败 stub 禁止；真实 UID/绑定挂载仍由 Docker 门禁验证。

本轮原始检查证据保存在 `.validation/pre-push-final/`，不随源码上传。上传后先按 README 使用 `publish=false` 运行 Actions。源码上传无需等待以下镜像发布阻塞消除。

## 原先确认的镜像扫描阻塞（本轮已修复已核实命中）

原扫描器对官方依赖二进制中的公开编译路径和普通 Token 常量报错。此前已用锁定 Node 24.14.0 复现 `personal_home_path`、`nonempty_secret_assignment`。本轮按本文开头的来源、归档哈希、成员哈希及命中指纹完成精确修复；真实最终镜像仍须在 Actions 中扫描。

安装目录 `.tools` 未进入 Git 或 Docker 源码上下文，镜像依赖由锁文件重新安装。扫描失败即停止的规则继续生效，任何新命中须核实来源和精确内容；不允许跳过整个依赖目录、二进制或安全门禁。

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
| GitHub Workflow | PASS（本地静态检查） | 两个 Workflow 均通过 actionlint 1.7.12；默认只验收，显式发布时也必须先扫描已构建本地候选镜像并通过 Compose/gVisor 合成集成门禁，最后推送同一候选。未执行远端 Workflow，扫描误报与实际 Docker 门禁仍待解决 |

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

以上证据齐全且镜像扫描误报妥善解决后才能改为 `READY_TO_PUBLISH`。当前源码已达到 `READY_TO_PUSH`，可先上传私有仓库并手动执行只验证的 Actions；本轮没有创建远端仓库或执行上传、镜像发布。
