# Changelog

本仓库遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本。

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
