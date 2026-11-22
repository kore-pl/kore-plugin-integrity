# Changelog

本仓库遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本。

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
