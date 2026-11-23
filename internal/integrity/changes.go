package integrity

import "strings"

// ChangeEntry 是 check 结果里的一条结构化变更（带严重度），供主壳告警中心与前端消费。
type ChangeEntry struct {
	// Type 是变更类型：added / removed / modified。
	Type string `json:"type"`
	// Path 是变更文件的绝对路径。
	Path string `json:"path"`
	// Severity 是 critical（系统二进制/配置）或 warning（普通文件）。
	Severity string `json:"severity"`
}

// criticalPathPrefixes 是"系统二进制 / 配置"的判定前缀：命中即 critical。
// 口径保持保守：只覆盖标准系统目录，插件数据目录与用户文件一律 warning。
var criticalPathPrefixes = []string{
	"/etc/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/boot/",
	"/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/",
	"/usr/local/bin/", "/usr/local/sbin/", "/usr/local/lib/",
}

// severityOfPath 按路径判定严重度：系统二进制/配置 → critical，其余 → warning。
func severityOfPath(path string) string {
	clean := strings.TrimSpace(path)
	for _, prefix := range criticalPathPrefixes {
		if strings.HasPrefix(clean, prefix) {
			return SeverityCritical
		}
	}
	return SeverityWarning
}

// buildChanges 把三态差异摊平成带 severity 的 changes[]：删除 → 篡改 → 新增，
// 与 alerts 的顺序一致；无差异时返回空数组（不是 null）。
func buildChanges(result CheckResult) []ChangeEntry {
	changes := make([]ChangeEntry, 0, len(result.Removed)+len(result.Modified)+len(result.Added))
	for _, path := range result.Removed {
		changes = append(changes, ChangeEntry{Type: "removed", Path: path, Severity: severityOfPath(path)})
	}
	for _, entry := range result.Modified {
		changes = append(changes, ChangeEntry{Type: "modified", Path: entry.Path, Severity: severityOfPath(entry.Path)})
	}
	for _, path := range result.Added {
		changes = append(changes, ChangeEntry{Type: "added", Path: path, Severity: severityOfPath(path)})
	}
	return changes
}
