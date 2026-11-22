# kore-plugin-integrity

kore 的**关键文件完整性插件**：对关键文件建立 sha256 基线，按需比对篡改/新增/删除。
`info.json.depth_level = "basic"`、`lifecycle = "lazy"`。

## 定位与边界

- 协议：`kore.plugin.v1`，唯一第三方依赖 `github.com/pengtang1024/kore/pkg/pluginapi v0.1.1`（其余为标准库）。
- 只做**完整性与防篡改**：计算 sha256 与元数据、落基线、比对三态、单文件校验。
  不做 root 提权、不做事件投递、不读文件内容、不改被扫描文件。
- 资源：`memory_mb: 6`、`cpu_quota: 10%`、`pids_max: 16`；流式哈希，常驻内存不随文件大小增长。

## 方法表

| 方法（裸名 / 全名） | 入参 | 行为与返回 |
| --- | --- | --- |
| `integrity.baseline` / `baseline` | `{paths[], exclude?[]}` | 递归扫描并落基线（快照语义，再次调用覆盖）。返回 `{saved, entries, total_bytes, duration_ms, previous_entries, warnings?}` |
| `integrity.check` / `check` | `{paths?, exclude?}` | 与基线比对。`paths` 省略时沿用基线扫描根；`exclude` 省略时沿用基线排除规则。返回 `{ok, added[], removed[], modified[], unchanged, checked_at, warnings?}` |
| `integrity.status` / `status` | 无 | 基线元信息：`{has_baseline, created_at, entries, total_bytes, last_check_at, last_check_ok}`；从未建立的字段为 `null` |
| `integrity.verify_file` / `verify_file` | `{path, expected_sha256}` | 单文件校验：`{match, actual_sha256, expected_sha256}` |

`modified[]` 每条为 `{path, old_sha256, new_sha256, old_mode, new_mode, changes[]}`，
`changes` 只取 `sha256` / `mode` 两项——文件内容或权限位变化都会被抓到。

`added` / `removed` 是路径字符串数组；`ok = len(added)+len(removed)+len(modified) == 0`。

### 基线文件

`<KORE_STATE_DIR>/baseline.json`，权限 0600，原子写入（临时文件 + fsync + rename）。
结构：`{version, created_at, roots[], exclude[], entries[], total_bytes, last_check_at?, last_check_ok?}`，
`entries[]` 每项 `{path, sha256, size, mode, mtime, uid, gid}`。
`check` 会回写 `last_check_at` / `last_check_ok`，不改动 `entries`（基线仍是建立时的快照）。

无基线时 `check` 返回 `E_NOTFOUND` + `detail.hint = "先调用 integrity.baseline 建立基线"`。

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
make dist    # 产出 dist/integrity-0.2.0.tar.gz（info.json + bin/integrity + SHA256SUMS）与同名 .sha256
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

- 变更告警事件投递（`kore.event` / `plugin.alert`）与阈值策略。
- cgroup 资源超限下的行为细化（当前依赖单文件/条目上限兜底）。
