// Package e2e 用真实插件二进制 + Unix socket 跑 L2 全链路，作为发版前的最终验收。
//
// 覆盖：baseline → check 三态（unchanged / modified / removed / added）→ verify_file
// → 基线缺失 E_NOTFOUND。白名单根固定为 /tmp/kore-integrity-test，由
// KORE_INTEGRITY_ALLOW_ROOTS 显式追加；状态目录落在临时目录，与扫描根物理隔离。
package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// testRoot 是 E2E 约定的白名单扫描根。
const testRoot = "/tmp/kore-integrity-test"

// pluginSession 是握手后的会话。
type pluginSession struct {
	t      *testing.T
	cmd    *exec.Cmd
	conn   net.Conn
	done   chan error
	stderr *bytes.Buffer
}

// buildPlugin 用当前源码构建插件二进制，保证测的是工作树而不是旧产物。
func buildPlugin(t *testing.T) string {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if preset := os.Getenv("KORE_INTEGRITY_E2E_BIN"); preset != "" {
		if !filepath.IsAbs(preset) {
			preset = filepath.Join(repoRoot, preset)
		}
		if _, err := os.Stat(preset); err != nil {
			t.Fatalf("KORE_INTEGRITY_E2E_BIN 指向的二进制不可用: %v", err)
		}
		return preset
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("缺少 go 工具链，跳过 E2E")
	}
	bin := filepath.Join(t.TempDir(), "integrity")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", bin, ".")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("构建插件失败: %v\n%s", err, out)
	}
	return bin
}

// startPlugin 起 UDS 监听并拉起插件进程，返回握手后的会话。
func startPlugin(t *testing.T, bin, stateDir string) *pluginSession {
	t.Helper()
	sockDir, err := os.MkdirTemp("", "kore-int-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "plugin.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("监听 UDS 失败: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	unixListener, ok := listener.(*net.UnixListener)
	if ok {
		_ = unixListener.SetDeadline(time.Now().Add(20 * time.Second))
	}

	cmd := exec.Command(bin)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	cmd.Env = append(os.Environ(),
		"KORE_PLUGIN_SOCK="+sock,
		"KORE_PLUGIN_ID=integrity",
		"KORE_STATE_DIR="+stateDir,
		"KORE_INTEGRITY_ALLOW_ROOTS="+testRoot,
		"KORE_LOG_LEVEL=error",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动插件进程失败: %v", err)
	}
	session := &pluginSession{t: t, cmd: cmd, done: make(chan error, 1), stderr: stderr}
	t.Cleanup(func() {
		select {
		case <-session.done:
		default:
			_ = cmd.Process.Kill()
			<-session.done
		}
		if t.Failed() {
			t.Logf("插件 stderr:\n%s", stderr.String())
		}
	})

	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("等待插件连接失败: %v", err)
	}
	if ok {
		_ = unixListener.SetDeadline(time.Time{})
	}
	session.conn = conn
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		session.done <- cmd.Wait()
		close(session.done)
	}()

	request := session.readRequest()
	if request.Method != "kore.hello" {
		t.Fatalf("首帧方法=%q，期望 kore.hello", request.Method)
	}
	reply := &pluginapi.Response{
		Type: pluginapi.TypeResponse, ID: request.ID, ReqID: request.ReqID,
		Result: json.RawMessage(`{"ok":true,"protocol":"kore.plugin.v1"}`),
	}
	if err := pluginapi.WriteJSON(conn, reply); err != nil {
		t.Fatalf("回写 hello 失败: %v", err)
	}
	return session
}

// readRequest 读一帧 request。
func (s *pluginSession) readRequest() *pluginapi.Request {
	s.t.Helper()
	_ = s.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	payload, err := pluginapi.ReadFrame(s.conn, pluginapi.MaxFrameSize)
	if err != nil {
		s.t.Fatalf("读帧失败: %v", err)
	}
	env, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		s.t.Fatalf("解码帧失败: %v", err)
	}
	request, ok := env.(*pluginapi.Request)
	if !ok {
		s.t.Fatalf("帧类型是 %T，不是 request", env)
	}
	return request
}

// call 发一个业务请求并返回响应。
func (s *pluginSession) call(method string, params any) *pluginapi.Response {
	s.t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		s.t.Fatalf("序列化参数失败: %v", err)
	}
	request := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: "id-" + method, ReqID: "r-" + method, Method: method, Params: raw,
	}
	if err := pluginapi.WriteJSON(s.conn, request); err != nil {
		s.t.Fatalf("写请求失败: %v", err)
	}
	_ = s.conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	payload, err := pluginapi.ReadFrame(s.conn, pluginapi.MaxFrameSize)
	if err != nil {
		s.t.Fatalf("读响应失败: %v", err)
	}
	env, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		s.t.Fatalf("解码响应失败: %v", err)
	}
	response, ok := env.(*pluginapi.Response)
	if !ok {
		s.t.Fatalf("响应帧类型是 %T", env)
	}
	if response.ReqID != request.ReqID {
		s.t.Fatalf("req_id=%q，期望回显 %q", response.ReqID, request.ReqID)
	}
	return response
}

// mustResult 断言无错误并把 result 解码到 out。
func mustResult(t *testing.T, response *pluginapi.Response, out any) {
	t.Helper()
	if response.Error != nil {
		t.Fatalf("意外错误: code=%s message=%s", response.Error.Code, response.Error.Message)
	}
	if err := json.Unmarshal(response.Result, out); err != nil {
		t.Fatalf("解码 result 失败: %v (%s)", err, response.Result)
	}
}

// TestIntegrityE2E 是真实进程 + 真实文件系统的验收主链路。
func TestIntegrityE2E(t *testing.T) {
	bin := buildPlugin(t)
	stateDir := t.TempDir()

	if err := os.RemoveAll(testRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(testRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(testRoot) })

	files := map[string]string{"a.conf": "alpha", "b.conf": "bravo", "c.conf": "charlie"}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(testRoot, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	session := startPlugin(t, bin, stateDir)

	// 1) baseline：3 条。
	var baseline struct {
		Saved           bool     `json:"saved"`
		Entries         int      `json:"entries"`
		TotalBytes      int64    `json:"total_bytes"`
		PreviousEntries int      `json:"previous_entries"`
		Warnings        []string `json:"warnings"`
	}
	response := session.call("integrity.baseline", map[string]any{"paths": []string{testRoot}})
	mustResult(t, response, &baseline)
	if !baseline.Saved || baseline.Entries != 3 || baseline.PreviousEntries != 0 {
		t.Fatalf("baseline=%+v，期望 saved=true entries=3 previous=0", baseline)
	}
	if baseline.TotalBytes != int64(len("alphabravocharlie")) {
		t.Fatalf("total_bytes=%d", baseline.TotalBytes)
	}
	t.Logf("baseline: saved=%v entries=%d total_bytes=%d duration_ms 字段见原始 JSON: %s",
		baseline.Saved, baseline.Entries, baseline.TotalBytes, response.Result)

	// 2) 未改动：ok=true，unchanged=3。
	checkCounts(t, session, "unchanged", 0, 0, 0, 3)

	// 3) 改 1 个文件：modified=1。
	modifiedFile := filepath.Join(testRoot, "a.conf")
	if err := os.WriteFile(modifiedFile, []byte("alpha-tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	checkCounts(t, session, "modified", 0, 0, 1, 2)

	// 4) 重新建基线（覆盖语义），再删 1 个：removed=1。
	var second struct {
		Entries         int `json:"entries"`
		PreviousEntries int `json:"previous_entries"`
	}
	response = session.call("integrity.baseline", map[string]any{"paths": []string{testRoot}})
	mustResult(t, response, &second)
	if second.Entries != 3 || second.PreviousEntries != 3 {
		t.Fatalf("二次 baseline=%+v，期望 entries=3 previous=3", second)
	}
	if err := os.Remove(filepath.Join(testRoot, "b.conf")); err != nil {
		t.Fatal(err)
	}
	checkCounts(t, session, "removed", 0, 1, 0, 2)

	// 5) 重新建基线，加 1 个：added=1。
	response = session.call("integrity.baseline", map[string]any{"paths": []string{testRoot}})
	mustResult(t, response, &second)
	if err := os.WriteFile(filepath.Join(testRoot, "d.conf"), []byte("delta"), 0o644); err != nil {
		t.Fatal(err)
	}
	checkCounts(t, session, "added", 1, 0, 0, 2)

	// 6) verify_file：正确摘要 true，错误摘要 false。
	content, err := os.ReadFile(modifiedFile)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	correct := hex.EncodeToString(sum[:])
	var verify struct {
		Match          bool   `json:"match"`
		ActualSHA256   string `json:"actual_sha256"`
		ExpectedSHA256 string `json:"expected_sha256"`
	}
	response = session.call("integrity.verify_file", map[string]string{"path": modifiedFile, "expected_sha256": correct})
	mustResult(t, response, &verify)
	if !verify.Match || verify.ActualSHA256 != correct {
		t.Fatalf("verify_file 正确摘要=%+v，期望 match=true", verify)
	}
	wrong := "0000000000000000000000000000000000000000000000000000000000000000"
	response = session.call("integrity.verify_file", map[string]string{"path": modifiedFile, "expected_sha256": wrong})
	mustResult(t, response, &verify)
	if verify.Match {
		t.Fatalf("verify_file 错误摘要应 match=false: %+v", verify)
	}

	// 7) 删基线后 check 回 E_NOTFOUND；status 回到 has_baseline=false。
	baselinePath := filepath.Join(stateDir, "baseline.json")
	if _, err := os.Stat(baselinePath); err != nil {
		t.Fatalf("基线文件应存在: %v", err)
	}
	if err := os.Remove(baselinePath); err != nil {
		t.Fatal(err)
	}
	response = session.call("integrity.check", map[string]any{})
	if response.Error == nil || response.Error.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("删基线后 check 期望 E_NOTFOUND，实际 error=%+v result=%s", response.Error, response.Result)
	}
	if !bytes.Contains(response.Error.Detail, []byte("integrity.baseline")) {
		t.Fatalf("E_NOTFOUND 应带 hint: %s", response.Error.Detail)
	}
	var status struct {
		HasBaseline bool `json:"has_baseline"`
		Entries     int  `json:"entries"`
	}
	response = session.call("integrity.status", map[string]any{})
	mustResult(t, response, &status)
	if status.HasBaseline || status.Entries != 0 {
		t.Fatalf("无基线 status=%+v，期望 has_baseline=false", status)
	}

	// 优雅关停。
	shutdown := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: "id-shutdown", ReqID: "r-shutdown", Method: "kore.shutdown",
	}
	if err := pluginapi.WriteJSON(session.conn, shutdown); err != nil {
		t.Fatalf("写 shutdown 失败: %v", err)
	}
	_ = session.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := pluginapi.ReadFrame(session.conn, pluginapi.MaxFrameSize); err != nil {
		t.Fatalf("读 shutdown 响应失败: %v", err)
	}
}

// checkCounts 执行一次 check 并断言三态计数与 unchanged。
func checkCounts(t *testing.T, session *pluginSession, step string, added, removed, modified, unchanged int) {
	t.Helper()
	var result struct {
		OK       bool     `json:"ok"`
		Added    []string `json:"added"`
		Removed  []string `json:"removed"`
		Modified []struct {
			Path    string   `json:"path"`
			Changes []string `json:"changes"`
		} `json:"modified"`
		Unchanged int      `json:"unchanged"`
		CheckedAt string   `json:"checked_at"`
		Warnings  []string `json:"warnings"`
	}
	response := session.call("integrity.check", map[string]any{})
	mustResult(t, response, &result)
	if len(result.Added) != added || len(result.Removed) != removed || len(result.Modified) != modified {
		t.Fatalf("%s check=%+v，期望 added=%d removed=%d modified=%d", step, result, added, removed, modified)
	}
	if result.Unchanged != unchanged {
		t.Fatalf("%s unchanged=%d，期望 %d", step, result.Unchanged, unchanged)
	}
	wantOK := added == 0 && removed == 0 && modified == 0
	if result.OK != wantOK {
		t.Fatalf("%s ok=%v，期望 %v", step, result.OK, wantOK)
	}
	if result.CheckedAt == "" {
		t.Fatalf("%s checked_at 不应为空", step)
	}
	t.Logf("%s check: ok=%v added=%d removed=%d modified=%d unchanged=%d raw=%s",
		step, result.OK, len(result.Added), len(result.Removed), len(result.Modified), result.Unchanged, response.Result)
}
