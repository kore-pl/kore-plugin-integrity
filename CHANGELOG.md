# Changelog

本仓库遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本。

## [0.6.0] - 2026-11-25

### Added

- **`check` 的 `modified[]` 带体积三件套** `old_size` / `new_size` / `size_delta`
  （`internal/integrity/methods.go`）：基线条目自 0.1.0 起就落盘了 `Entry.Size`
  （`scan.go` `newEntry`），所以**旧基线也能量出体积变化**，不需要重建基线。
  `changes[]` 仍只报 `sha256` / `mode`——体积变化不作为第三种判定原因，既有消费方
  对 `changes` 长度的断言不受影响。纯可加性字段，无破坏性协议变化。
- **`baseline.list` 回报扫描根 `roots`**：结果级 `roots` 是当前基线的扫描根；每个版本
  条目带自己的 `roots`（随 `baselines/index.json` 落盘，`SnapshotMeta.Roots`）。
  上界 keep(100) × paths(256)，默认 keep=10 时约 100 KiB 量级（G-03）。0.6.0 之前归档的
  快照索引里没有该字段，读取为空数组 = "当时没记"，不是"没有路径"。
- **扫描历史 `scans.json` + `status.scan_history`**：每次 `check` 追加一条汇总
  （时刻 / 基线 id / 结论 / 新增·修改·删除·未变化·跳过计数 / 截断 / 耗时），只保留最近
  `MaxScanHistory=20` 次，落盘上界约 4 KiB（20 × ~200 B）。**只记计数不记逐文件明细**：
  明细会让落盘与内存随扫描次数线性膨胀（G-03），逐文件明细仍由主壳前端按次留存。
  该文件是**辅助轨道**：损坏时按空处理并在下一次 `check` 覆盖重写（自愈），
  不让一条历史日志把 `check` / `status` 拖死；基线与快照索引仍严格 fail-closed。

### Changed

- 主壳前端 `web/integrity.js` 消费以上三处字段：变更表的「变化」列显示
  `1.2 KiB → 1.4 KiB (+200 B)`；概览「扫描范围」改用 `baseline.list.roots` 真值
  （不再依赖本页 localStorage 记忆）；新增「扫描历史」面板（换浏览器也在）。
  旧版本插件（无这些字段）时前端逐项回退到原有口径并显示「—」，不崩。

### Notes

- **发行产物（`dist/`）与索引/签名未在本轮重建**：按任务卡约束，`make dist` 与
  `kore-plugins` 索引重签留到发版批次；因此 `info.json.size_bytes` 仍是 0.5.1 的量级，
  下次 `make dist` 会按固定点算法回收口值。
- 领域文档（`kore/docs/PLUGIN-MATURITY.md` 的完整性行 / 方法数）不在本仓写域，
  留给 docs owner 收口。

## [0.5.1] - 2026-11-24

### Changed

- **`depth_level`: `production` → `basic`**. Upgrade criterion ① in `kore/docs/PLUGIN-CATALOG.md` §6.1 (boundary cases: invalid input / concurrency / insufficient permission / resource exhaustion, each ≥1 case wired into CI) is **not met** — this repo has no `tests/boundary/` and `grep -rn "t.Parallel" tests/` returns 0. Fault injection (criterion ②) passes, but both must hold; the previous `production` claim was an **over-declaration** and the index value `basic` is correct. **Not a regression defect**: no code, capability or method-contract change; production can be re-claimed once boundary cases land.

## [0.5.0] - 2026-11-24

### Changed

- **`integrity.verify_file` 单列方法级能力 `system:read`**（ADR-0047）：内核
  `methodActionPattern` 放宽字符集接受下划线后，只读校验方法不再回退到插件级最高要求
  `system:admin`，`invoke` 审计口径恢复「只读不写管理类审计」。协议表达能力变化 →
  minor bump（`0.4.0` → `0.5.0`，版本号变化改 dist sha，按 [docs/RELEASE.md] 要求 bump）。
- **测试熔断器按 ADR-0047 解除并反向**：`tests/fault/declaration_test.go` 由「不得声明
  verify_file」改为「必须声明且只能 `system:read`」；`capabilities_test.go` 的
  `TestVerifyFileUndeclared` 反转为 `TestVerifyFileReadOnlyDeclared`。

## [0.4.0] - 2026-11-23

### Added

- **定时扫描（交给内核 scheduler）**：`integrity.schedule.set` 生成可 POST 到
  `/api/v1/scheduler/tasks` 的任务描述（`integrity.check`，默认 `0 4 * * *`），返回
  `{id, schedule, next_run, next_run_at, recommended_task}`；`integrity.schedule.get` 读回本地描述。
  插件内**零 ticker / 零定时 goroutine**（G-19），真正的调度由内核 scheduler 负责。
- **结构化变更与告警**：`check.changes[]` 摊平 added/removed/modified 并带 `severity`
  （critical=系统二进制/配置：`/etc`、`/bin`、`/sbin`、`/lib*`、`/boot`、`/usr/{bin,sbin,lib}*`、
  `/usr/local/{bin,sbin,lib}`；其余 warning），与 `alerts[]` 一起供主壳告警中心消费（插件不发通知）。
- **恢复后自动复核**：`integrity.restore` 成功后立即跑一次 `check`，返回
  `{verified, changes, alerts[], message}`；仍有差异时 message 明确「恢复成功但复核发现仍有 N 处
  不一致」，避免把"恢复基线记录"误读成"文件已回滚干净"。

### Tests

- `recheck_test.go`：恢复后复核两种结局（仍有差异 / 无差异）、severity 判据、任务三要素与幂等。

## [0.3.3] - 2026-11-23

### 新增

- **`integrity.restore`（`system:admin`）**：把 `baselines/<id>` 历史快照恢复为当前
  `baseline.json`，返回 `{from_id, to_id, entries, restored, backup_path?, hint}`；
  覆盖前把当前基线复制为 `<state>/baseline.bak.<UTC 纳秒>.json`（0600）并归档进历史，
  恢复后仍可再回滚；已是目标版本时 `restored=false` 且不写盘、不产生备份；
  不存在 id 返回 `E_NOTFOUND` + 可用 id 列表 hint；写入仍限定插件 state（零侵入 G-31）。
- `info.json.method_capabilities` 增加 `integrity.restore: system:admin`。

## [0.3.2] - 2026-11-23

### Changed

- 提升为 `production` 深度等级（故障注入测试已覆盖）

## [0.3.1] - 2026-11-23

### 修复

- fix: 插件级 capabilities 补 system:admin（方法级含 admin 方法，原声明会误导用户启用确认的范围）
  - `baseline` / `schedule.set` 是 `system:admin`，但 `info.json.capabilities` 只声明了
    `system:read`——用户在商店启用时只确认了 read，实际却有 admin 方法（能力放大）。
  - 插件级改为 `["system:read", "system:admin"]`，`manifest.json` 同步；方法级声明不变。
  - `capabilities_test.go` 同步：断言插件级两项且与 manifest 一致，并新增「方法级不得强于
    插件级」的本地校验；`TestVerifyFileUndeclared` 如实反映 verify_file 回退到插件级域。

## [0.3.0] - 2026-11-23

### 新增

- **方法级 capability（§3.5 #12）**：`info.json.method_capabilities` 声明
  `baseline` / `schedule.set` 为 `system:admin`，`baseline.list` / `check` / `status` /
  `schedule.get` 为 `system:read`；插件级 `capabilities` 保持 `system:read`。
  `verify_file` 因内核 `methodActionPattern` 不允许下划线而无法进表，有效能力回退到
  插件级 `system:read`（`capabilities_test.go` 锁定该事实）。
- **基线多版本**：`baseline` 支持 `note`（≤200 字符）与 `keep`（1..100，缺省 10），
  每次生成 `baseline-<UTC 纳秒>` 快照；旧当前基线先归档到 `<state>/baselines/<id>.json`
  再替换，历史元信息存 `<state>/baselines/index.json`（不含 entries，避免一次加载全部历史）。
  0.2.0 的单文件基线（`version=1`）仍可读，`id` 按 `created_at` 派生，再建基线时自动归档。
- **指定基线比对**：`check` 新增 `baseline_id`（空/`latest` = 当前），可对历史快照比对；
  `check` 回写所选快照的 `last_check_at` / `last_check_ok`。
- **`integrity.baseline.list`**：列出当前与历史快照元信息（`limit` 1..100），
  返回 `{baselines[], count, keep}`。
- **告警聚合**：`check` 新增 `summary{added,removed,modified,unchanged,skipped}` 与
  `alerts[]`（`file_removed`/`file_modified`=critical，`file_added`/`scan_incomplete`=warning，
  每条含 `code/severity/metric/count/message/hint`）；**不发通知**（G-10 不出网）。
- **恢复边界显式化**：`check` 新增 `recovery{supported:false, owner:"backup",
  method:"backup.restore", hint}`——本仓只做检测，不保存文件内容，回滚由 `backup` 插件负责。
- **定时扫描（交给内核 scheduler）**：`integrity.schedule.set` 输出内核 scheduler 可消费的
  任务描述（对齐 `backup.schedule.set`：`created=false`、`task_id=""`、`next_run_at`、
  `recommended_task{name,plugin,method,params,schedule,timeout_s}`），默认 `0 4 * * *`、
  `timeout_s` 1800；`integrity.schedule.get` 读回本地描述。**插件内零 ticker / 零 AfterFunc /
  零定时 goroutine**（G-19），`g19_test.go` 对源码做静态门禁。
- `status` 新增 `baseline_count` / `latest_id` / `latest_note`。

### 变更

- 当前基线仍是 `<state>/baseline.json`（0600 原子写）；历史快照与索引同为 0600，
  索引损坏时 `baseline.list` / 新 `baseline` 显式 `E_INTERNAL`，不静默丢历史。
- 版本 `0.2.0` → `0.3.0`（新增方法，minor）；`manifest.json` 同步版本。

### 测试

- 方法级 capability 表驱动：语法（内核 methodActionPattern）、取值、覆盖与预期一致、
  `verify_file` 兜底；零 ticker 静态门禁。
- 基线多版本：归档/列表/指定旧基线比对/保留裁剪/说明与 keep 边界/旧格式兼容/
  索引损坏 fail-closed/0600 权限。
- 告警：四类告警表驱动（code/severity/metric/count/顺序）、三态同时出现与无差异空数组、
  恢复指引 `supported=false`。
- 定时扫描：任务描述契约、绑定历史基线、无基线/非法 cron/超时/路径/未知快照拒绝、
  损坏描述 fail-closed、cron 下次执行时间。

## [0.2.0] - 2026-11-23

### 新增

- **真实文件完整性校验（去 noop）**，业务方法由占位摘要升级为四个可用方法：
  - `integrity.baseline {paths[], exclude?[]}`：对文件/目录（递归）计算 sha256 + 元数据
    （`path` / `sha256` / `size` / `mode` / `mtime` / `uid` / `gid`），存 `<state>/baseline.json`（0600），
    返回 `{saved, entries, total_bytes, duration_ms, previous_entries, warnings?}`；基线是快照，再次调用覆盖。
  - `integrity.check {paths?, exclude?}`：对比当前状态与基线，返回
    `{ok, added[], removed[], modified[], unchanged, checked_at, warnings?}`；`paths` 省略时沿用基线扫描根，
    `exclude` 省略时沿用基线排除规则；`modified` 逐条给出 old/new sha256、old/new mode 与 `changes`。
  - `integrity.status`：返回 `{has_baseline, created_at, entries, total_bytes, last_check_at, last_check_ok}`。
  - `integrity.verify_file {path, expected_sha256}`：单文件校验，返回
    `{match, actual_sha256, expected_sha256}`；期望摘要大小写归一化。
- 目录递归上限（深度 10 / 条目 10000）、单文件 8 GiB 上限；超限、权限不足、越界符号链接
  一律跳过并进入 `warnings[]`，不失败整个调用。

### 安全

- 路径白名单改为 `/etc`、`/usr/bin`、`/usr/sbin`、`/opt`、`/var/www`、`<state>`；
  其余根须由 `KORE_INTEGRITY_ALLOW_ROOTS`（冒号分隔）显式追加，非法值启动即失败。
- 符号链接二次归属：`ResolveExisting` 词法校验 + `EvalSymlinks` 后真实路径再判定白名单，
  拒绝逃逸链接；递归中不跟随符号链接目录（防环）。
- 只计算 sha256，文件内容永不进入响应；基线原子写入（临时文件 + fsync + rename）。

### 变更

- **破坏性**：旧骨架方法 `integrity.verify` 移除，由 `integrity.check`（基线比对）与
  `integrity.verify_file`（单文件校验）取代——入参与语义均不同，0.x 阶段按次版本升级处理。
- `main.go` / `README.md` 去掉"骨架 / 占位摘要 / 不读宿主文件系统"口径，补充方法、安全与上限说明。

### 测试

- 单元：白名单拒绝 `/root`、symlink 逃逸拒绝、glob 排除、added/removed/modified 三态、
  mode 变更、无基线 `E_NOTFOUND`、基线损坏 `E_INTERNAL`、状态目录不可写 `E_INTERNAL`。
- 真实 E2E（`tests/e2e`）：真实插件二进制 + UDS + `/tmp/kore-integrity-test` 三文件，
  覆盖 baseline → unchanged=3 → modified=1 → removed=1 → added=1 → verify_file 真/假 →
  删基线后 `E_NOTFOUND`。
- `tests/fault/` 四类：kill（断连/半包）、timeout（超时 + 恢复）、disk full（状态目录不可写）、
  permission / oversize（跳过 + warning）。

## [0.1.1] - 2026-11-23

- build: 位级可复现打包（stage chmod + tar --mode 归一、size_bytes 收敛），二进制改嵌 manifest.json，消除同版本 sha 漂移

## [0.1.0] - 2026-11-22

### 新增

- 首个 M5 批 1 文件完整性插件骨架（`depth_level = basic`、`lifecycle = lazy`），协议 `kore.plugin.v1` / 能力 `system:read` / 资源 `memory_mb: 6`。
- `kore.hello` 三步握手：发 `kore.hello`（§5 全字段 + `id`/`token` 别名）→ 读响应帧 → 校验 `ok`/`id`/协议主版本。
- 会话循环：读帧 → 按 `method` 分发 → 写 `response`，回显 `id` 与 `req_id`；未知方法回 `E_NOTFOUND`。
- 完整性方法 `integrity.baseline` / `integrity.verify`：路径白名单校验 + 结构化结果；骨架口径下用 sha256 标准库对路径取占位摘要（`scanned:false`），**不读取宿主文件系统**。
- 路径白名单：仅接受 `/etc`、`/usr/local/etc`、`/opt/kore`、`/var/www` 下的规范绝对路径；拒绝相对路径、`..` 穿越、控制字符与白名单外路径；单次 ≤256 条。
- `tests/fault/`：基础故障注入——kill（连接强制中断）、timeout（读 deadline）、半包帧、超时恢复闭环。
- `Makefile`：`build` / `dist`（回填 `size_bytes`、生成包内 `SHA256SUMS` 与包旁 `.sha256`）/ `check` / `clean`；确定性打包显式列条目 + `gzip -9n`。
- 单测：`net.Pipe` 模拟主壳侧，覆盖握手、两个完整性方法、占位摘要稳定性、非法参数与 `req_id` 回显。

### 说明

- 真实哈希扫描、基线持久化与变更告警落盘留待生产级迭代；本版本不得标“生产级 / 开箱可用”。
