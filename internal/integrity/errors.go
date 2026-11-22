package integrity

import (
	"encoding/json"
)

// hintDetail 把人类可读的"下一步怎么办"编码进错误体 detail.hint。
// 错误体 schema 固定为 {code,message,detail}，detail 只放这一个字段。
func hintDetail(hint string) json.RawMessage {
	payload, err := json.Marshal(struct {
		Hint string `json:"hint"`
	}{Hint: hint})
	if err != nil {
		return nil
	}
	return payload
}
