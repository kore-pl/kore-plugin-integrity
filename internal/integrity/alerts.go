package integrity

import "fmt"

// 告警严重度：critical 表示安全相关（删除 / 篡改），warning 表示需要关注但不直接判定为攻击。
const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
)

// 告警指标口径固定，前端与告警中心可直接按 metric 聚合。
const (
	MetricRemovedFiles  = "removed_files"
	MetricModifiedFiles = "modified_files"
	MetricAddedFiles    = "added_files"
	MetricSkipped       = "skipped_entries"
)

// CheckAlert 是检测到差异时返回的结构化告警。
//
// 本插件**不发送通知**（G-10 不出网）：告警只出现在 check 结果体里，
// 由主壳告警中心 / 前端决定如何展示与投递。
type CheckAlert struct {
	// Code 是稳定告警码（file_removed / file_modified / file_added / scan_incomplete）。
	Code string `json:"code"`
	// Severity 是 critical 或 warning。
	Severity string `json:"severity"`
	// Metric 是计数指标名，便于跨插件聚合。
	Metric string `json:"metric"`
	// Count 是该指标的条目数。
	Count int `json:"count"`
	// Message 是一句话说明。
	Message string `json:"message"`
	// Hint 是下一步怎么办（人类可读）。
	Hint string `json:"hint"`
}

// RecoveryGuide 是"能不能恢复、由谁恢复"的显式声明。
//
// 本插件只做检测，不保存文件内容，因此 Supported 恒为 false；
// 恢复能力归属 backup 插件（跨插件指引，不越界实现备份存储）。
type RecoveryGuide struct {
	Supported bool   `json:"supported"`
	Owner     string `json:"owner"`
	Method    string `json:"method"`
	Hint      string `json:"hint"`
}

// buildSummary 汇总三态与跳过条数。
func buildSummary(result CheckResult, skipped int) CheckSummary {
	return CheckSummary{
		Added:     len(result.Added),
		Removed:   len(result.Removed),
		Modified:  len(result.Modified),
		Unchanged: result.Unchanged,
		Skipped:   skipped,
	}
}

// buildAlerts 按固定顺序把差异聚合为告警：删除 → 篡改 → 新增 → 扫描不完整。
// 无差异且无跳过时返回空数组（不是 null）。
func buildAlerts(result CheckResult, truncated bool) []CheckAlert {
	alerts := make([]CheckAlert, 0, 4)
	if count := len(result.Removed); count > 0 {
		alerts = append(alerts, CheckAlert{
			Code:     "file_removed",
			Severity: SeverityCritical,
			Metric:   MetricRemovedFiles,
			Count:    count,
			Message:  fmt.Sprintf("基线中的 %d 个文件已消失", count),
			Hint:     "先确认是否预期下线；若疑似被删除，用 backup 插件从最近备份恢复文件，再重新执行 integrity.baseline",
		})
	}
	if count := len(result.Modified); count > 0 {
		alerts = append(alerts, CheckAlert{
			Code:     "file_modified",
			Severity: SeverityCritical,
			Metric:   MetricModifiedFiles,
			Count:    count,
			Message:  fmt.Sprintf("%d 个文件的内容或权限位发生变化", count),
			Hint:     "按 modified[] 的 old/new sha256 与 mode 定位变更；确认异常时用 backup.restore 恢复后重建基线",
		})
	}
	if count := len(result.Added); count > 0 {
		alerts = append(alerts, CheckAlert{
			Code:     "file_added",
			Severity: SeverityWarning,
			Metric:   MetricAddedFiles,
			Count:    count,
			Message:  fmt.Sprintf("发现 %d 个未纳入基线的新文件", count),
			Hint:     "确认新增来源；来源不明时用 backup 插件对比同路径备份，预期变更后重新执行 integrity.baseline 更新基线",
		})
	}
	if count := len(result.Warnings); count > 0 || truncated {
		message := fmt.Sprintf("扫描有 %d 条跳过/告警，结论可能不完整", count)
		if truncated {
			message = fmt.Sprintf("扫描被条目上限截断（%d 条跳过/告警），结论可能不完整", count)
		}
		alerts = append(alerts, CheckAlert{
			Code:     "scan_incomplete",
			Severity: SeverityWarning,
			Metric:   MetricSkipped,
			Count:    count,
			Message:  message,
			Hint:     "检查 warnings[] 中的路径与扫描上限（深度 10 / 条目 10000 / 单文件 8 GiB）",
		})
	}
	return alerts
}

// recoveryGuide 给出跨插件恢复指引；不实现任何恢复动作。
func recoveryGuide(result CheckResult) RecoveryGuide {
	guide := RecoveryGuide{
		Supported: false,
		Owner:     "backup",
		Method:    "backup.restore",
		Hint:      "本插件只做完整性检测、不保存文件内容，无法自行回滚；请用 backup 插件（backup.list / backup.restore）从已知良好的备份包恢复，恢复后重新执行 integrity.baseline",
	}
	if result.OK {
		guide.Hint = "本次无差异；如需回滚能力，请确保 backup 插件对相同路径有可用备份"
	}
	return guide
}
