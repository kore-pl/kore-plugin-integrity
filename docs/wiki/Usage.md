# 使用

## 方法概览

`integrity.baseline` / `baseline.list` / `restore` / `check` / `status` / `verify_file` / `schedule.set` / `schedule.get`——建立 sha256 基线、比对篡改、恢复历史快照、单文件校验、生成定时扫描任务描述。

完整参数表与返回字段见仓库 [README](https://github.com/kore-pl/kore-plugin-integrity#readme) 与中文 [DETAIL.md](../DETAIL.md)。方法名与 JSON 字段是语言无关的标识符，各语言文档保持一致。

## 典型调用

1. 通过 kore 内核的插件调用接口发送 JSON-RPC 请求，方法名取上表裸名或全名。
2. 读返回体的 `schema` / `count` / `truncated` 等字段；截断标记为真时缩小范围重试。
3. 写类方法通常需要二次确认参数（如 `confirm: true`）与目标名。

## 语言文档

[简体中文](../DETAIL.md) · [English](../DETAIL.en.md) · [Español](../DETAIL.es.md) · [Français](../DETAIL.fr.md) · [Deutsch](../DETAIL.de.md) · [Русский](../DETAIL.ru.md) · [Português](../DETAIL.pt.md)
