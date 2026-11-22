# kore-plugin-integrity

kore 的 **M5 批 1 文件完整性插件骨架**（关键文件哈希基线 + 变更告警）。
`info.json.depth_level = "basic"`、`lifecycle = "lazy"`。

## 定位与边界

- 协议：`kore.plugin.v1`，唯一第三方依赖 `github.com/pengtang1024/kore/pkg/pluginapi v0.1.1`（其余为标准库）。
- **骨架口径**：`integrity.baseline` / `integrity.verify` 只做路径白名单校验与 sha256 占位摘要
  （对路径字符串取摘要，`scanned:false`，`size_bytes:0`），**不读取宿主文件系统、不写宿主文件**。
- 路径白名单静态校验：`/etc`、`/usr/local/etc`、`/opt/kore`、`/var/www` 及其子路径；
  拒绝相对路径、非规范路径、`..` 穿越、控制字符与白名单外路径。
- 基础级边界用例延 v1.1；真实哈希扫描与告警落盘留待生产级迭代，不得标“生产级 / 开箱可用”。

## 方法表

| 方法（裸名 / 全名） | 行为 |
| --- | --- |
| `integrity.baseline` / `baseline` | 校验 `paths` → 返回 `{baseline_id, scanned:false, count, entries[]}`，每条含路径与 sha256 占位摘要 |
| `integrity.verify` / `verify` | 校验 `paths` → 返回 `{baseline_id, scanned:false, changed:0, alert:false, changes[]}` |
| `kore.ping` / `kore.reload` / `kore.shutdown` | 协议必选方法；`kore.reload` 无外部配置，`config_digest` 为空 |

`paths` 约束：非空、≤256 条、每条为白名单根下的规范绝对路径。
响应帧一律回显请求的 `id` 与 `req_id`；未知方法回 `E_NOTFOUND`；参数非法回 `E_INVALID`。

## 环境变量

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `KORE_PLUGIN_SOCK` | 是 | 主壳创建的 UDS 路径 |
| `KORE_PLUGIN_ID` | 否 | 内核登记 id，缺省取内嵌 `info.json.id` |
| `KORE_PLUGIN_TOKEN` | 否 | 内核注入令牌；当前只随 `kore.hello` 上报 |
| `KORE_LOG_LEVEL` | 否 | `debug`/`info`/`warn`/`error`，缺省 `warn`；日志只写 stderr |

`stdout` 只留给协议帧，任何日志都不得写 stdout。

## 构建与打包

```bash
make build   # CGO_ENABLED=0 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin/integrity .
make dist    # 产出 dist/integrity-0.1.0.tar.gz（info.json + bin/integrity + SHA256SUMS）与同名 .sha256
make check   # gofmt → go vet → go test -timeout 200s
```

`dist` 按包内实际字节数三轮不动点回填 `info.json.size_bytes`（仓库清单保持 `0`，打包脚本写真实值）。
打包确定性：显式列条目（`info.json` 为首、无 `./` 根条目）、`--mtime=@0`、`--owner=0 --group=0 --numeric-owner`、`gzip -9n`。

本地联调依赖**不提交**的 `go.work`（`use .` + `use ../kore/pkg/pluginapi`）；跨仓 `replace` 禁止写入 `go.mod`（G-17）。

## 未完成项（生产级迭代）

- 真实文件哈希扫描与基线持久化（当前为占位摘要，`scanned:false`）。
- 变更告警事件投递（`kore.event` / `plugin.alert`）与阈值策略。
- 磁盘满 / cgroup 超限四类完整故障注入（当前仅基础 kill/timeout 两类）。
