# kore-plugin-integrity（关键文件完整性插件）

## 它做什么

对关键文件建立 **sha256 基线**，之后按需比对，报告文件被篡改、新增或删除。插件只读文件、计算哈希与元数据，**不读文件内容、不改被扫描文件、不提权、不投递事件**。深度等级 `basic`，生命周期 `lazy`，协议 `kore.plugin.v1`。

## 定位与边界

- 唯一第三方依赖 `github.com/pengtang1024/kore/pkg/pluginapi v0.1.1`，其余为标准库。
- 资源：`memory_mb: 6`、`cpu_quota: 10%`、`pids_max: 16`；流式哈希，常驻内存不随文件大小增长。
- 不做内容备份与恢复（归 `backup` 插件）；不做 root 提权、不做事件投递。

## 方法与能力

| 方法 | 入参 | 行为 |
| --- | --- | --- |
| `integrity.baseline` / `baseline` | `{paths[], exclude?[], note?, keep?}` | 递归扫描生成新基线快照（旧快照进入历史）。`keep` 为保留快照总数，1..100，缺省 10。 |
| `integrity.baseline.list` / `baseline.list` | `{limit?}` | 列出当前与历史基线快照；`roots` 是当前基线的扫描根（0.6.0 起）。 |
| `integrity.restore` / `restore` | `{baseline_id}` | 把历史快照恢复为当前基线，覆盖前备份当前基线并自动复核。 |
| `integrity.check` / `check` | `{paths?, exclude?, baseline_id?}` | 与指定基线比对，返回 `added/removed/modified/changes[]`；`severity` 区分关键与普通文件。 |
| `integrity.status` / `status` | 无 | 当前基线、历史数量与最近 20 次扫描历史。 |
| `integrity.verify_file` / `verify_file` | `{path, expected_sha256}` | 单文件 sha256 校验。 |
| `integrity.schedule.set` / `schedule.set` | `{schedule?, timeout_s?, paths?, exclude?, baseline_id?}` | 生成内核 scheduler 可消费的定时扫描任务描述，不创建任务、不起 ticker。 |
| `integrity.schedule.get` / `schedule.get` | `{name?}` | 读回本地保存的任务描述。 |

读方法声明 `system:read`；`baseline` / `restore` / `schedule.set` 为 `system:admin`；插件级声明 `system:read` + `system:admin`（方法级只收窄、不放大）。`verify_file` 因内核方法名语法不含下划线无法进表，回退到插件级声明。

## 告警类型

`file_removed`（基线文件消失，critical）、`file_modified`（sha256 或权限位变化，critical）、`file_added`（新文件，warning）、`scan_incomplete`（扫描跳过或条目上限截断，warning）。本版只返回 `alerts[]`，不投递通知。

## 安装与验证

从插件市场安装 `integrity`，或用 `make dist` 产出 `dist/integrity-0.6.0.tar.gz` 后按 kore 安装器流程导入。开发验证：`make check`（gofmt → go vet → go test -timeout 200s）；发布前 `make dist` 连跑两次核对 sha256 一致。
