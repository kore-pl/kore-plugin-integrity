# kore-plugin-integrity

kore 的**关键文件完整性插件**：对关键文件建立 sha256 基线，按需比对篡改/新增/删除。
`info.json.depth_level = "basic"`、`lifecycle = "lazy"`；方法级能力：读方法 `system:read`、
`baseline` / `restore` / `schedule.set` 为 `system:admin`；插件级声明 `system:read` + `system:admin`
（方法级只收窄、不放大，用户在商店启用时确认的能力覆盖全部方法）。`verify_file` 因内核
方法名语法不含下划线无法进表，回退到插件级声明。

## 定位与边界

- 协议：`kore.plugin.v1`，唯一第三方依赖 `github.com/pengtang1024/kore/pkg/pluginapi v0.1.1`（其余为标准库）。
- 只做**完整性与防篡改**：计算 sha256 与元数据、落基线、比对三态、单文件校验。
  不做 root 提权、不做事件投递、不读文件内容、不改被扫描文件。
- 资源：`memory_mb: 6`、`cpu_quota: 10%`、`pids_max: 16`；流式哈希，常驻内存不随文件大小增长。

## 方法表

| 方法（裸名 / 全名） | 入参 | 行为与返回 |
| --- | --- | --- |
| `integrity.baseline` / `baseline` | `{paths[], exclude?[], note?, keep?}` | 递归扫描并生成新基线快照（旧快照进入历史）。`keep` 为保留快照总数（含当前，1..100，缺省 10）。返回 `{saved, id, note?, entries, total_bytes, duration_ms, previous_entries, archived_id?, kept, baseline_count, warnings?}` |
| `integrity.baseline.list` / `baseline.list` | `{limit?}` | 列出当前与历史基线快照（不含 entries）：`{baselines[], count, keep, roots[]}`（`roots` 是**当前基线**的扫描根，0.6.0 起）；每条含 `id/created_at/note?/entries/total_bytes/last_check_at?/last_check_ok?/current/roots?` |
| `integrity.restore` / `restore` | `{baseline_id}` | 把历史快照恢复为当前基线：覆盖前把当前基线备份为 `<state>/baseline.bak.<ts>.json` 并归档进历史；返回 `{from_id, to_id, entries, restored, backup_path?, hint, verified, changes, alerts[], message?}`；恢复成功后自动跑一次 check 复核（`verified` + 变更数，仍有差异时 message 明说） |
| `integrity.check` / `check` | `{paths?, exclude?, baseline_id?}` | 与指定基线比对（`baseline_id` 空/`latest` = 当前）。返回 `{ok, baseline_id, added[], removed[], modified[], changes[], unchanged, checked_at, truncated, summary, alerts[], recovery, warnings?}`；`changes[]` 带 `severity`（critical=系统二进制/配置，warning=普通文件） |
| `integrity.status` / `status` | 无 | 当前基线 + 历史数量 + 扫描历史：`{has_baseline, created_at, entries, total_bytes, last_check_at, last_check_ok, baseline_count, latest_id, latest_note?, scan_history[]}`；从未建立的字段为 `null`；`scan_history` 恒为数组（0.6.0 起，最近 20 次汇总，最新在前） |
| `integrity.verify_file` / `verify_file` | `{path, expected_sha256}` | 单文件校验：`{match, actual_sha256, expected_sha256}` |
| `integrity.schedule.set` / `schedule.set` | `{schedule?, timeout_s?, paths?, exclude?, baseline_id?}` | 生成内核 scheduler 可消费的定时扫描任务描述（**不创建任务、不起 ticker**），返回 `{created=false, task_id="", saved, id, schedule, next_run, next_run_at, recommended_task, hint}` |
| `integrity.schedule.get` / `schedule.get` | `{name?}` | 读回插件本地保存的任务描述：`{records[], count, hint}` |

`modified[]` 每条为 `{path, old_sha256, new_sha256, old_mode, new_mode, old_size, new_size, size_delta, changes[]}`，
`changes` 只取 `sha256` / `mode` 两项——文件内容或权限位变化都会被抓到；
体积三件套（0.6.0 起）是**可加性**字段：`size_delta = new_size - old_size`，
只改权限时为 `0`，不单独作为第三种 change 出现。

`added` / `removed` 是路径字符串数组；`ok = len(added)+len(removed)+len(modified) == 0`。

### 基线多版本

```text
<state>/baseline.json          当前（最新）基线（0600，临时文件 + fsync + rename 原子写）
<state>/baselines/<id>.json    历史快照（0600）
<state>/baselines/index.json   历史快照元信息（不含 entries，避免一次加载全部历史；0.6.0 起含 roots）
<state>/scans.json             最近 20 次 check 的汇总（0600；只记计数，不记逐文件明细）
```

- 每次 `baseline` 生成新快照 `baseline-<UTC 纳秒>`；旧当前基线先归档进历史，再替换当前。
- 归档失败不会覆盖当前基线（先写历史、后写当前），不会丢上一份可用基线。
- `keep` 保留最近 N 份（含当前）；超出部分删除并更新索引。`keep=1` 时只有当前基线。
- `check.baseline_id` 可指定历史快照（用 `baseline.list` 查看）；省略或 `latest` 用当前基线。
- 0.2.0 的单文件基线（`version=1`、无 `id`/`note`）仍可读，`id` 按 `created_at` 派生；
  再建基线时自动归档为历史快照。
- 无当前基线时 `check` 返回 `E_NOTFOUND` + `detail.hint = "先调用 integrity.baseline 建立基线"`；
  指定不存在的快照返回 `E_NOTFOUND` + hint 指向 `baseline.list`。

### 告警

`check` 在返回体里给 `alerts[]`（**不发通知**，G-10 不出网；投递归主壳告警中心）：

| code | metric | severity | 触发 |
| --- | --- | --- | --- |
| `file_removed` | `removed_files` | critical | 基线中的文件消失 |
| `file_modified` | `modified_files` | critical | sha256 或权限位变化 |
| `file_added` | `added_files` | warning | 出现未纳入基线的新文件 |
| `scan_incomplete` | `skipped_entries` | warning | 扫描有跳过/告警或条目上限截断 |

每条 alert 为 `{code, severity, metric, count, message, hint}`；`summary` 给出
`{added, removed, modified, unchanged, skipped}` 计数。无差异时 `alerts=[]`。

### 恢复 / 回滚边界（明确不做）

本插件只做检测：**不保存文件内容，也不提供恢复/回滚**。`check.recovery` 恒为
`{supported:false, owner:"backup", method:"backup.restore", hint}`，
引导用户用 `backup` 插件的 `backup.list` / `backup.restore` 从已知良好的备份包恢复，
恢复后重新执行 `integrity.baseline`。跨插件调用不在插件协议能力范围内，本仓不实现备份存储。

### 定时扫描（交给内核 scheduler）

- `schedule.set` **只返回任务描述，不创建内核任务**：`created=false`、`task_id=""`，
  契约与 `backup.schedule.set` 一致（`next_run_at` + `recommended_task{name,plugin,method,params,schedule,timeout_s}`）
- 把 `recommended_task` 原样 `POST /api/v1/scheduler/tasks` 才会真正生效；调度、错过补跑、
  并发互斥都由内核 scheduler 负责
- **插件内零 ticker / 零 AfterFunc / 零定时 goroutine**（G-19），lazy 插件空闲能真正退出；
  `g19_test.go` 对源码做静态门禁
- 默认 `0 4 * * *`（每天 04:00，与 backup 的 03:00 错开），`timeout_s` 缺省 1800（1–3600）
- 任务参数与 `integrity.check` 同构；可绑定 `baseline_id` 到某个历史快照
- 没有当前基线时 `schedule.set` 直接 `E_NOTFOUND`（避免装一个每天失败的任务）
- `schedule.get` 只读插件本地 `schedule.json`，不代表内核任务状态；内核任务请查
  `GET /api/v1/scheduler/tasks`

## 安全边界

- **路径白名单**：默认只允许 `/etc`、`/usr/bin`、`/usr/sbin`、`/opt`、`/var/www`、`<state>`。
  其他根必须由 `KORE_INTEGRITY_ALLOW_ROOTS`（冒号分隔的规范绝对路径）显式追加；非法值启动即失败。
- **符号链接逃逸**：先做词法校验（绝对、规范、白名单内、无控制字符），再 `EvalSymlinks`，
  真实路径必须仍在白名单内；不存在的路径解析最近的已存在祖先再判定，杜绝"尚不存在的路径"成为逃逸入口。
  递归中不跟随符号链接目录（防环），根外链接文件跳过并记 warning。
- **不读内容**：只流式计算 sha256，文件内容永不进入响应或日志。
- **上限**：目录递归深度 10、单次条目 10000、单文件 8 GiB；超限/权限不足/不可读一律跳过并写
  `warnings[]`，不让一条坏路径毁掉整次校验。
- **exclude**：glob 语义，不含 `/` 的模式匹配文件名（如 `*.log`），含 `/` 的模式匹配完整路径
  （如 `/proc/*`，会把该目录整棵子树排除）。

## 环境变量

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `KORE_PLUGIN_SOCK` | 是 | 主壳创建的 UDS 路径 |
| `KORE_STATE_DIR` | 业务方法必填 | 插件状态目录；基线落 `<状态>/baseline.json`。由内核注入 |
| `KORE_INTEGRITY_ALLOW_ROOTS` | 否 | 追加白名单根，冒号分隔，如 `/srv/app:/data` |
| `KORE_PLUGIN_ID` | 否 | 内核登记 id，缺省取内嵌 `manifest.json.id` |
| `KORE_PLUGIN_TOKEN` | 否 | 内核注入令牌；当前只随 `kore.hello` 上报 |
| `KORE_LOG_LEVEL` | 否 | `debug`/`info`/`warn`/`error`，缺省 `warn`；日志只写 stderr |

`stdout` 只留给协议帧，任何日志都不得写 stdout。

## 构建与打包

```bash
make build   # CGO_ENABLED=0 GOWORK=off GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin/integrity .
make dist    # 产出 dist/integrity-0.5.1.tar.gz（info.json + bin/integrity + SHA256SUMS）与同名 .sha256
make check   # gofmt → go vet → go test -timeout 200s
```

`dist` 从包体实际字节数收敛回填 `info.json.size_bytes`，并生成包内 `SHA256SUMS` 与包旁 `.sha256`。
打包确定性：显式列条目（`info.json` 为首、无 `./` 根条目）、`--mtime=@0`、`--owner=0 --group=0 --numeric-owner`、
`--mode` 归一、`gzip -9n`；同一源码在任意干净 clone 重打包 sha256 一致。

本地联调依赖**不提交**的 `go.work`（`use .` + `use ../kore/pkg/pluginapi`）；跨仓 `replace` 禁止写入 `go.mod`（G-17）。

## 测试

```bash
GOWORK=off go test -timeout 200s ./...            # 单元 + E2E + fault
GOWORK=off go test -v -run TestIntegrityE2E ./tests/e2e
```

- `internal/integrity/*_test.go`：白名单、symlink 逃逸、glob、深度/条目/大小上限、
  added/removed/modified、mode 变更、无基线、基线损坏、状态目录不可写。
- `tests/e2e`：真实二进制 + UDS + `/tmp/kore-integrity-test`，跑完整三态与 verify_file。
- `tests/fault`：kill / timeout / disk full / permission+oversize 四类。

## 未完成项（后续迭代）

- 告警投递（`kore.event` / `plugin.alert`）与阈值/去重策略：本版只返回 `alerts[]`，不投递。
- 恢复/回滚：明确不做（内容不在本仓存储，归 `backup` 插件；见上文边界）。
- 前端页面：不在本仓范围（主壳 `web/integrity.js` 由主壳仓维护）。
- cgroup 资源超限下的行为细化（当前依赖单文件/条目上限兜底）。

<!-- oss:begin -->
## 开源与贡献

[![CI](https://github.com/kore-pl/kore-plugin-integrity/actions/workflows/ci.yml/badge.svg)](https://github.com/kore-pl/kore-plugin-integrity/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go 1.26](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](go.mod)

本仓库是 **kore** 的 `关键文件完整性插件`（id `integrity`），独立仓库、独立版本线、独立 CI（少触发：push main / tag / PR / 手动）。内核与协议见 [kore](https://github.com/kore-pl/kore)。

- **许可**：MIT（inbound = outbound，不要求 CLA）；提交用 `git commit -s` 签 DCO。
- **贡献**：[CONTRIBUTING.md](CONTRIBUTING.md)（构建、门禁、发版、边界）。
- **安全**：[SECURITY.md](SECURITY.md)——漏洞不要开公开 issue。
- **行为准则**：[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。
- **兼容性**：`protocol: kore.plugin.v1` · `requires_kore: >=0.1.0 <0.2.0` · `lifecycle: lazy` · 深度等级 `basic`。
- **验证方式**：本地 `make check` 优先（CI 只在 push main / tag / PR / 手动跑；发布前 `make dist` 连跑两次核对 sha 一致）。
- **发布产物**：`make dist` → `dist/integrity-0.5.1.tar.gz` + `.sha256`（位级可复现，连跑两次 sha 相同）。
- **相关仓库**：[索引 kore-plugins](https://github.com/kore-pl/kore-plugins) · [协议文档](https://github.com/kore-pl/kore/blob/main/docs/PLUGIN-PROTOCOL.md) · [SDK 指南](https://github.com/kore-pl/kore/blob/main/docs/PLUGIN-SDK.md)

<!-- oss:end -->
