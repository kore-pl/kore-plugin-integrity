package fault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pengtang1024/kore-plugin-integrity/internal/integrity"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestBaselineListCorruptNotSilent 历史索引或当前基线损坏时 baseline.list 必须报错，
// 不能只回"当前这一条"或"空列表"：
// 那会让用户以为历史基线全没了（或从来没建过），而真实情况是状态文件坏了。
func TestBaselineListCorruptNotSilent(t *testing.T) {
	t.Run("历史索引损坏", func(t *testing.T) {
		fixture := newFaultFixture(t, map[string]string{"a.txt": "alpha"})
		first := baselineOK(t, fixture.service, []string{fixture.root})
		second := baselineOK(t, fixture.service, []string{fixture.root})
		if first.ID == second.ID {
			t.Fatalf("两次基线得到同一 id %q，无法构造历史快照", first.ID)
		}

		// 对照：健康状态 = 当前 + 1 条历史，且恰好一条 Current。
		healthy := callOK[integrity.BaselineListResult](t, fixture.service, "baseline.list", nil)
		if healthy.Count != 2 || len(healthy.Baselines) != 2 {
			t.Fatalf("健康状态 count=%d records=%d，期望 2", healthy.Count, len(healthy.Baselines))
		}
		currents := 0
		for _, item := range healthy.Baselines {
			if item.Current {
				currents++
			}
		}
		if currents != 1 {
			t.Fatalf("健康状态 current 标记数=%d，期望恰好 1", currents)
		}
		if healthy.Baselines[0].ID != second.ID {
			t.Fatalf("首条（最新）id=%q，期望当前基线 %q", healthy.Baselines[0].ID, second.ID)
		}

		// 故障：索引损坏 → 必须显式失败，不能只回当前那一条。
		indexPath := filepath.Join(fixture.state, "baselines", "index.json")
		if err := os.WriteFile(indexPath, []byte("{broken"), 0o600); err != nil {
			t.Fatalf("写坏索引: %v", err)
		}
		perr := callFault(t, fixture.service, "baseline.list", nil)
		if perr.Code != pluginapi.E_INTERNAL {
			t.Fatalf("code=%s，期望 E_INTERNAL（索引损坏不得静默丢历史）", perr.Code)
		}
		t.Logf("索引损坏显式报错: %s %s", perr.Code, perr.Message)
	})

	t.Run("当前基线损坏", func(t *testing.T) {
		fixture := newFaultFixture(t, map[string]string{"a.txt": "alpha"})
		baselineOK(t, fixture.service, []string{fixture.root})

		// 故障：当前基线损坏 → 必须显式失败，不能只回历史 = 悄无声息地"当前基线消失"。
		if err := os.WriteFile(filepath.Join(fixture.state, "baseline.json"), []byte("{broken"), 0o600); err != nil {
			t.Fatalf("写坏当前基线: %v", err)
		}
		perr := callFault(t, fixture.service, "baseline.list", nil)
		if perr.Code != pluginapi.E_INTERNAL {
			t.Fatalf("code=%s，期望 E_INTERNAL（当前基线损坏不得静默跳过）", perr.Code)
		}
		t.Logf("当前基线损坏显式报错: %s %s", perr.Code, perr.Message)
	})
}
