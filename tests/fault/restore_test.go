package fault_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/pengtang1024/kore-plugin-integrity/internal/integrity"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// restoreRequest 是 integrity.restore 的入参形状。
type restoreRequest struct {
	BaselineID string `json:"baseline_id"`
}

// TestRestoreFaultKeepsCurrentBaseline 状态目录不可写时 restore 必须回 E_INTERNAL，
// 且**原基线一个字节都不能变**：
//
// 恢复失败最坏的结局不是"没恢复"，而是把用户唯一的那份当前基线弄丢/写坏——
// restore 的顺序是「备份当前基线 → 归档 → 覆盖」，任何一步失败都必须整体回滚，
// 本条用例锁的就是"备份这一步失败时，baseline.json 原封不动"。
func TestRestoreFaultKeepsCurrentBaseline(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 无视目录权限，跳过权限用例")
	}
	fixture := newFaultFixture(t, map[string]string{"a.txt": "alpha"})
	first := baselineOK(t, fixture.service, []string{fixture.root})
	second := baselineOK(t, fixture.service, []string{fixture.root})
	if first.ID == second.ID {
		t.Fatalf("两次基线得到同一 id %q，无法构造历史快照", first.ID)
	}

	currentPath := filepath.Join(fixture.state, "baseline.json")
	before, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatalf("读取当前基线: %v", err)
	}
	if status := callOK[integrity.StatusResult](t, fixture.service, "status", nil); status.LatestID == nil || *status.LatestID != second.ID {
		t.Fatalf("恢复前当前基线=%v，期望 %q", status.LatestID, second.ID)
	}

	// 状态目录不可写：模拟磁盘满 / 权限被收回。
	if err := os.Chmod(fixture.state, 0o500); err != nil {
		t.Fatalf("chmod 状态目录: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(fixture.state, 0o700) })

	perr := callFault(t, fixture.service, "restore", restoreRequest{BaselineID: first.ID})
	if perr.Code != pluginapi.E_INTERNAL {
		t.Fatalf("code=%s，期望 E_INTERNAL（备份当前基线失败必须显式失败，不能谎报 restored）", perr.Code)
	}
	t.Logf("restore 显式失败: %s %s", perr.Code, perr.Message)

	// 恢复写权限后核对：原基线必须逐字节一致。
	if err := os.Chmod(fixture.state, 0o700); err != nil {
		t.Fatalf("恢复状态目录权限: %v", err)
	}
	after, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatalf("恢复失败后读不到当前基线（原基线被毁）: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("恢复失败后 baseline.json 被改写：before=%d bytes after=%d bytes", len(before), len(after))
	}
	status := callOK[integrity.StatusResult](t, fixture.service, "status", nil)
	if !status.HasBaseline || status.LatestID == nil || *status.LatestID != second.ID {
		t.Fatalf("恢复失败后当前基线被改：has_baseline=%v latest_id=%v，期望仍为 %q",
			status.HasBaseline, status.LatestID, second.ID)
	}
	if status.Entries != second.Entries {
		t.Fatalf("恢复失败后当前基线条目=%d，期望 %d", status.Entries, second.Entries)
	}
	if list := callOK[integrity.BaselineListResult](t, fixture.service, "baseline.list", nil); list.Count != 2 {
		t.Fatalf("恢复失败后历史基线数=%d，期望 2（失败不得删/加历史）", list.Count)
	}

	// 失败不留半成品：不该有备份文件，也不该有未清理的临时文件。
	for _, pattern := range []string{"baseline.bak.*", ".tmp-*"} {
		matches, globErr := filepath.Glob(filepath.Join(fixture.state, pattern))
		if globErr != nil {
			t.Fatalf("glob %s: %v", pattern, globErr)
		}
		if len(matches) > 0 {
			t.Fatalf("恢复失败后残留半成品 %s: %v", pattern, matches)
		}
	}
}
