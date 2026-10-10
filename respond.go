package authgate

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// 错误码。
const (
	errUnauthorized     = "unauthorized"
	errForbidden        = "forbidden"
	errCSRF             = "csrf_rejected"
	errMethodNotAllowed = "method_not_allowed"
	errNotFound         = "not_found"
	errInvalidParam     = "invalid_param"
	errUserNotFound     = "user_not_found"
	errUserIsAdmin      = "user_is_admin"
	errCannotDeleteSelf = "cannot_delete_self"
	errKeyNotFound      = "key_not_found"
	errKeyLimit         = "key_limit_reached"
	errLastKey          = "last_key"
	errTooFrequent      = "too_frequent"
	errRateLimited      = "rate_limited"
	errSendFailed       = "send_failed"
	errInvalidCode      = "invalid_code"
	errCodeExpired      = "code_expired"
	errTooManyAttempts  = "too_many_attempts"
	errStorage          = "storage_error"
)

// errorMessages 是错误码对应的中文提示。
var errorMessages = map[string]string{
	errUnauthorized:     "未登录或凭证无效",
	errForbidden:        "没有权限执行此操作",
	errCSRF:             "请求来源校验失败",
	errMethodNotAllowed: "不支持的请求方法",
	errNotFound:         "接口不存在",
	errInvalidParam:     "参数错误",
	errUserNotFound:     "用户不存在",
	errUserIsAdmin:      "不能删除配置中的管理员",
	errCannotDeleteSelf: "不能删除自己",
	errKeyNotFound:      "key 不存在",
	errKeyLimit:         "key 数量已达上限",
	errLastKey:          "不能删除最后一个 key",
	errTooFrequent:      "发送过于频繁，请稍后再试",
	errRateLimited:      "请求过于频繁，请稍后再试",
	errSendFailed:       "验证码发送失败，请稍后重试",
	errInvalidCode:      "验证码错误",
	errCodeExpired:      "验证码已失效，请重新获取",
	errTooManyAttempts:  "错误次数过多，请重新获取验证码",
	errStorage:          "保存用户文件失败",
}

// writeJSON 输出 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, v any) error {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// writeError 输出错误响应。extra 中的 retry_after（秒）会同时写入 Retry-After header。
func writeError(w http.ResponseWriter, status int, code string, extra map[string]any) error {
	body := map[string]any{"error": code, "message": errorMessages[code]}
	for k, v := range extra {
		body[k] = v
	}
	if ra, ok := extra["retry_after"]; ok {
		switch n := ra.(type) {
		case int:
			w.Header().Set("Retry-After", strconv.Itoa(n))
		case int64:
			w.Header().Set("Retry-After", strconv.FormatInt(n, 10))
		}
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="authgate"`)
	}
	return writeJSON(w, status, body)
}

// seconds 将时长向上取整为秒数，至少 1。
func seconds(d time.Duration) int {
	s := int((d + time.Second - 1) / time.Second)
	if s < 1 {
		s = 1
	}
	return s
}
