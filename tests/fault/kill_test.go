// Package fault_test 对 integrity 做故障注入，验证异常路径的结构化行为：
//
//  1. kill：内核侧强制断开（含半包帧），插件侧必须立刻返回错误而不是 hang；
//  2. timeout：hello 预算内对端不回响应 + deadline 清除后的恢复闭环；
//  3. disk full：状态目录不可写时基线保存失败，回 E_INTERNAL 而不是谎报 saved；
//  4. permission / oversize：不可读文件与超大文件跳过并记 warning，不失败整个调用；
//     同族权限故障在 verify_file 上必须显式报错，不能回 match=false；
//  5. restore：恢复失败（状态目录不可写）回 E_INTERNAL 且原基线逐字节不变、不留半成品；
//  6. schedule.get / schedule.set：schedule.json 损坏必须报错（不得静默返回空计划 /
//     不得覆盖损坏文件），状态目录不可写时不得谎报 saved；
//  7. baseline.list：历史索引或当前基线损坏必须报错，不得静默丢历史 / 丢当前；
//  8. 声明漂移：method_capabilities 必须过内核 methodActionPattern（否则整份清单
//     fail-closed），verify_file 因下划线按设计回退插件级能力。
package fault_test

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestKillFault 模拟内核侧在握手响应前被强制关闭（kill -9 语义），
// 验证插件侧 ReadFrame 立刻得到 io.EOF，不 panic、不 hang。
func TestKillFault(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = pluginConn.Close() }()
	_ = kernelConn.Close() // 内核侧突然消失

	done := make(chan error, 1)
	go func() {
		_, err := pluginapi.ReadFrame(pluginConn, pluginapi.MaxFrameSize)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("kill 后期望 io.EOF，实际 %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("kill 后读帧未在 3s 内返回，疑似 hang")
	}
}

// TestShortFrameFault 模拟内核侧只写了 2 字节帧头就断开（半包 kill），
// 验证 ReadFrame 返回短帧错误而非静默当作正常帧。
func TestShortFrameFault(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = pluginConn.Close() }()

	go func() {
		_, _ = kernelConn.Write([]byte{0x00, 0x02}) // 声明 2 字节载荷，只写帧头一半
		_ = kernelConn.Close()
	}()

	done := make(chan error, 1)
	go func() {
		_, err := pluginapi.ReadFrame(pluginConn, pluginapi.MaxFrameSize)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("半包帧期望错误，实际 nil")
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, pluginapi.ErrShortFrame) &&
			!errors.Is(err, io.EOF) {
			t.Fatalf("半包帧错误类型不符: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("半包帧未在 3s 内返回，疑似 hang")
	}
}

// TestTimeoutFault 模拟对端在 hello 预算内不回响应，验证 deadline 生效、
// 不会永久阻塞。
func TestTimeoutFault(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = pluginConn.Close() }()
	defer func() { _ = kernelConn.Close() }()

	const budget = 300 * time.Millisecond
	if err := pluginConn.SetReadDeadline(time.Now().Add(budget)); err != nil {
		t.Fatalf("设置读 deadline 失败: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := pluginapi.ReadFrame(pluginConn, pluginapi.MaxFrameSize)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("期望超时错误，实际 nil")
		}
		var netErr net.Error
		if errors.As(err, &netErr) && !netErr.Timeout() {
			t.Fatalf("期望 timeout 错误，实际 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("读帧未按 deadline 触发，疑似 hang")
	}
}

// TestDeadlineRecover 模拟 deadline 触发后对端恢复并正确发帧，
// 验证清除 deadline 后连接可继续用于正常请求（故障恢复闭环）。
func TestDeadlineRecover(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = pluginConn.Close() }()
	defer func() { _ = kernelConn.Close() }()

	if err := pluginConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _ = pluginapi.ReadFrame(pluginConn, pluginapi.MaxFrameSize)
	_ = pluginConn.SetReadDeadline(time.Time{})

	go func() {
		_ = pluginapi.WriteJSON(kernelConn, &pluginapi.Request{
			Type: pluginapi.TypeRequest, ID: "id-1", Method: "integrity.status",
		})
	}()

	payload, err := pluginapi.ReadFrame(pluginConn, pluginapi.MaxFrameSize)
	if err != nil {
		t.Fatalf("恢复后读帧失败: %v", err)
	}
	env, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		t.Fatalf("恢复后解码失败: %v", err)
	}
	if req, ok := env.(*pluginapi.Request); !ok || req.Method != "integrity.status" {
		t.Fatalf("恢复后帧不符: %#v", env)
	}
}
