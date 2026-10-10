// Package keygen 生成并解析 AuthGate API key。
//
// 标准格式：sk- + 8 位 hex Unix 秒 + 16 位 hex 随机数，共 27 字符。
package keygen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// Prefix 是标准 key 的前缀。
const Prefix = "sk-"

// Len 是标准 key 的长度。
const Len = len(Prefix) + 8 + 16

var stdRe = regexp.MustCompile(`^sk-[0-9a-f]{24}$`)

// New 以 now 为创建时间生成一个新 key。
func New(now time.Time) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("keygen: crypto/rand failed: " + err.Error())
	}
	return fmt.Sprintf("%s%08x%s", Prefix, uint32(now.Unix()), hex.EncodeToString(b[:]))
}

// IsStandard 报告 key 是否为标准格式。
func IsStandard(key string) bool {
	return stdRe.MatchString(key)
}

// CreatedAt 从标准 key 中解析创建时间；非标准 key 返回 false。
func CreatedAt(key string) (time.Time, bool) {
	if !IsStandard(key) {
		return time.Time{}, false
	}
	sec, err := strconv.ParseUint(key[3:11], 16, 32)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(int64(sec), 0).UTC(), true
}

// Mask 返回用于日志的掩码形式：前 7 位 + … + 后 4 位。
func Mask(key string) string {
	if len(key) <= 11 {
		return "…"
	}
	return key[:7] + "…" + key[len(key)-4:]
}
