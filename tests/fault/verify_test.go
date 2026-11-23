package fault_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pengtang1024/kore-plugin-integrity/internal/integrity"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// verifyFileRequest 是 integrity.verify_file 的入参形状。
type verifyFileRequest struct {
	Path           string `json:"path"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

// zeroDigest 是一个格式合法但几乎不可能命中的期望摘要。
const zeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

// TestVerifyFilePermissionFault verify_file 必须把"读不到"报成错误，
// 不能回 match=false 让用户以为"文件内容与预期不符"——那是结论错误，比报错更危险。
func TestVerifyFilePermissionFault(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 无视文件权限，跳过权限用例")
	}
	fixture := newFaultFixture(t, map[string]string{"good.txt": "good", "bad.txt": "bad"})
	goodPath := filepath.Join(fixture.root, "good.txt")
	badPath := filepath.Join(fixture.root, "bad.txt")
	goodDigest := sha256Hex("good")
	badDigest := sha256Hex("bad")

	if err := os.Chmod(badPath, 0o000); err != nil {
		t.Fatalf("chmod 不可读文件: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(badPath, 0o644) })

	// 正例：摘要一致 → match=true，并回显实际摘要。
	match := callOK[integrity.VerifyFileResult](t, fixture.service, "verify_file", verifyFileRequest{
		Path: goodPath, ExpectedSHA256: goodDigest,
	})
	if !match.Match || match.ActualSHA256 != goodDigest || match.ExpectedSHA256 != goodDigest {
		t.Fatalf("摘要一致时 result=%+v，期望 match=true 且两侧摘要均为 %s", match, goodDigest)
	}

	// 摘要不一致是"结论"不是"故障"：回 match=false，不报错。
	mismatch := callOK[integrity.VerifyFileResult](t, fixture.service, "verify_file", verifyFileRequest{
		Path: goodPath, ExpectedSHA256: zeroDigest,
	})
	if mismatch.Match {
		t.Fatalf("摘要不一致时 match=true，把篡改当成通过")
	}
	if mismatch.ActualSHA256 != goodDigest {
		t.Fatalf("不一致时 actual_sha256=%q，期望 %q", mismatch.ActualSHA256, goodDigest)
	}

	// 故障：0o000 不可读——**即使期望摘要本来就是对的**也必须报错，
	// 不能因为"算术上对得上"就回 match=true，也不能回 match=false。
	perr := callFault(t, fixture.service, "verify_file", verifyFileRequest{
		Path: badPath, ExpectedSHA256: badDigest,
	})
	if perr.Code != pluginapi.E_INVALID {
		t.Fatalf("不可读文件 code=%s，期望 E_INVALID（不可读必须报错）", perr.Code)
	}
	t.Logf("不可读文件显式报错: %s %s", perr.Code, perr.Message)

	// 目录不是文件：必须拒绝，不能把目录当成"读不到的文件"。
	if dirErr := callFault(t, fixture.service, "verify_file", verifyFileRequest{
		Path: fixture.root, ExpectedSHA256: goodDigest,
	}); dirErr.Code != pluginapi.E_INVALID {
		t.Fatalf("目录 code=%s，期望 E_INVALID", dirErr.Code)
	}

	// 路径不存在：E_NOTFOUND（可操作错误，区别于"不可读"）。
	missing := filepath.Join(fixture.root, "missing.txt")
	if missingErr := callFault(t, fixture.service, "verify_file", verifyFileRequest{
		Path: missing, ExpectedSHA256: goodDigest,
	}); missingErr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("不存在路径 code=%s，期望 E_NOTFOUND", missingErr.Code)
	}

	// 摘要格式非法：先校摘要再碰文件系统——用不存在的路径 + 非法摘要，
	// 期望 E_INVALID（若先去解析路径就会得到 E_NOTFOUND，说明校验顺序被打乱）。
	if bad := callFault(t, fixture.service, "verify_file", verifyFileRequest{
		Path: missing, ExpectedSHA256: strings.Repeat("z", 64),
	}); bad.Code != pluginapi.E_INVALID {
		t.Fatalf("非法摘要 code=%s，期望 E_INVALID（摘要校验必须先于路径解析）", bad.Code)
	}
}
