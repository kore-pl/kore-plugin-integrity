# Changelog

本仓库遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本。

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
