package authgate

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// 无效 Bearer 的 IP 限流：60 次/分钟。
func TestBadBearerRateLimit(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	for i := 0; i < 60; i++ {
		expect(t, e.get(e.url("api", "/"), bearer(fmt.Sprintf("sk-bad-%03d-xxxxxxxx", i))), 401, "unauthorized")
	}
	r := e.get(e.url("api", "/"), bearer("sk-bad-final-xxxxxxxx"))
	expect(t, r, 429, "rate_limited")
	if r.header.Get("Retry-After") == "" {
		t.Errorf("missing Retry-After")
	}
	// 被限流期间有效 key 同样被拒绝（防止枚举），接口也受限
	expect(t, e.get(e.url("api", "/"), bearer(aliceKey)), 429, "rate_limited")
	expect(t, e.get(e.url("api", "/authgate/me"), bearer(aliceKey)), 429, "rate_limited")
	// Cookie 认证不受影响
	if r := e.get(e.url("web", "/"), e.cookie("alice")); r.status != 200 {
		t.Errorf("cookie blocked: %d", r.status)
	}
}

// T20：手工编辑用户文件 → 5 秒内生效。
func TestT20HotReload(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	const newKey = "sk-68e8c800dddddddddddddddd"
	expect(t, e.get(e.url("api", "/"), bearer(newKey)), 401, "")
	data, _ := os.ReadFile(e.file)
	edited := strings.Replace(string(data), bobKey+":bob\n", "", 1) + newKey + ":Carol\n"
	if err := os.WriteFile(e.file, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for time.Since(start) < 6*time.Second {
		if e.get(e.url("api", "/"), bearer(newKey)).status == 200 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	r := e.get(e.url("api", "/"), bearer(newKey))
	if r.status != 200 || !strings.Contains(r.body, "user=carol") {
		t.Fatalf("hot reload failed after %v: %d %s", time.Since(start), r.status, r.body)
	}
	t.Logf("reloaded within %v", time.Since(start).Round(100*time.Millisecond))
	expect(t, e.get(e.url("api", "/"), bearer(bobKey)), 401, "")
}

// T21：reload 前发送的验证码 reload 后仍可验证；冷却状态保留；新配置生效。
func TestT21ReloadKeepsState(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	expect(t, e.sendCode("alice"), 200, "")
	code := e.send.code("alice@example.com")

	e.extraGlb = "\tauthgate_admin alice\n\tauthgate_token_ttl 3h"
	e.load()

	expect(t, e.sendCode("alice"), 429, "too_frequent")
	r := e.validCode("alice", code)
	expect(t, r, 200, "")
	if r.json["is_admin"] != true || r.json["expires_in"].(float64) != 3*3600 {
		t.Errorf("new config not applied: %v", r.json)
	}
}

// 多次 reload 后旧 Core 被释放、后台协程退出。
func TestCoreReleasedOnStop(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	e.load()
	e.load()
	if _, ok := pool.References(e.file); !ok {
		t.Fatalf("core missing from pool")
	}
	if n, _ := pool.References(e.file); n != 3 {
		t.Errorf("references = %d, want 3 (one per site)", n)
	}
	e.stop()
	if _, ok := pool.References(e.file); ok {
		t.Errorf("core not released")
	}
}
