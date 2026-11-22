// Package fault_test 提供 integrity 插件的基础故障注入测试（骨架口径）。
//
// 基础级插件的核心路径用 net.Pipe 在协议层复刻 kill（连接强制中断）与
// timeout（读超时）两类故障，验证 pluginapi 帧读写面对异常对端时不 panic、
// 不 hang、错误可归类。不启动真实进程、不读取宿主文件系统。
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

// TestTimeoutFault 模拟对端在 hello 预算内不回响应，验证 SetReadDeadline
// 后 ReadFrame 按时返回 net.Error.Timeout，不会永久阻塞。
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

// TestShortFrameFault 模拟内核侧只写了 2 字节帧头就断开（半包 kill），
// 验证 ReadFrame 返回 ErrShortFrame 而非静默当作正常帧。
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

// TestDeadlineRecover 模拟 deadline 触发后对端恢复并正确发帧，
// 验证清除 deadline 后连接可继续用于正常握手（故障恢复闭环）。
func TestDeadlineRecover(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = pluginConn.Close() }()
	defer func() { _ = kernelConn.Close() }()

	// 先构造一次超时读。
	if err := pluginConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _ = pluginapi.ReadFrame(pluginConn, pluginapi.MaxFrameSize)
	_ = pluginConn.SetReadDeadline(time.Time{})

	// 恢复后正常写一帧 request。
	go func() {
		_ = pluginapi.WriteJSON(kernelConn, &pluginapi.Request{
			Type: pluginapi.TypeRequest, ID: "id-1", Method: "integrity.baseline",
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
	if req, ok := env.(*pluginapi.Request); !ok || req.Method != "integrity.baseline" {
		t.Fatalf("恢复后帧不符: %#v", env)
	}
}
