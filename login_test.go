package authgate

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func (e *env) sendCode(user string, hdr ...string) resp {
	return e.post(e.url("auto", "/authgate/code/send"), url.Values{"user": {user}}, hdr...)
}

func (e *env) validCode(user, code string) resp {
	return e.post(e.url("auto", "/authgate/code/valid"), url.Values{"user": {user}, "code": {code}})
}

func cookieFrom(r resp) *http.Cookie {
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if c.Name == "authgate_token" {
			return c
		}
	}
	return nil
}

// T01：浏览器访问 auto 站点，未登录 → 401 + 登录页。
func TestT01LoginPage(t *testing.T) {
	e := newEnv(t, defaultUsers, "\tauthgate_code_interval 45s")
	r := e.get(e.url("auto", "/some/page?x=1"), "Accept: text/html,application/xhtml+xml,*/*;q=0.8")
	if r.status != 401 || !strings.HasPrefix(r.header.Get("Content-Type"), "text/html") {
		t.Fatalf("status %d type %q", r.status, r.header.Get("Content-Type"))
	}
	if r.header.Get("Cache-Control") != "no-store" || r.header.Get("Content-Security-Policy") != loginCSP {
		t.Errorf("headers = %v", r.header)
	}
	for _, want := range []string{`var DOMAIN = "example.com";`, `var INTERVAL =  45 ;`, `autocomplete="one-time-code"`, `inputmode="numeric"`, `maxlength="6"`, "/authgate/"} {
		if !strings.Contains(r.body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(r.body, "http://") || strings.Contains(r.body, "https://") {
		t.Errorf("page must not reference external resources")
	}
}

// T08：验证码登录完整流程 → 设置 Cookie，刷新后正常访问。
func TestT08LoginFlow(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	r := e.sendCode("Alice@example.com")
	expect(t, r, 200, "")
	if r.json["user"] != "alice" || r.json["email"] != "alice@example.com" || r.json["expires_in"].(float64) != 300 || r.json["resend_after"].(float64) != 30 {
		t.Fatalf("send = %v", r.json)
	}
	if e.send.header.Get("X-Mail-Token") != "mail-secret" {
		t.Errorf("sendcode_header env placeholder not resolved: %v", e.send.header)
	}
	code := e.send.code("alice@example.com")
	if len(code) != 6 {
		t.Fatalf("code = %q", code)
	}

	jar := newJar(t)
	r = e.do(jar, http.MethodPost, e.url("auto", "/authgate/code/valid"), strings.NewReader("user=alice&code="+code), "Content-Type: application/x-www-form-urlencoded")
	expect(t, r, 200, "")
	if r.json["user"] != "alice" || r.json["is_admin"] != false || r.json["expires_in"].(float64) != 3600 {
		t.Errorf("valid = %v", r.json)
	}
	c := cookieFrom(r)
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.MaxAge != 3600 || c.Secure {
		t.Fatalf("cookie = %+v", c)
	}
	// 刷新后正常访问
	r = e.do(jar, http.MethodGet, e.url("auto", "/"), nil, "Accept: text/html")
	if r.status != 200 || !strings.Contains(r.body, "user=alice admin=false method=web") {
		t.Fatalf("after login: %d %s", r.status, r.body)
	}
	r = e.do(jar, http.MethodGet, e.url("auto", "/authgate/me"), nil)
	expect(t, r, 200, "")

	// logout
	r = e.do(jar, http.MethodGet, e.url("auto", "/authgate/logout"), nil, "Accept: text/html")
	if r.status != 302 || r.header.Get("Location") != "/" {
		t.Fatalf("logout html: %d %v", r.status, r.header)
	}
	if c := cookieFrom(r); c == nil || c.MaxAge >= 0 {
		t.Errorf("logout cookie = %+v", c)
	}
	expect(t, e.do(jar, http.MethodGet, e.url("auto", "/"), nil), 401, "")
	r = e.post(e.url("auto", "/authgate/logout"), nil)
	expect(t, r, 200, "")
	if r.json["logout"] != true {
		t.Errorf("logout = %v", r.json)
	}
}

// T09：30s 内重复发码 → 429 + retry_after。
func TestT09TooFrequent(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	expect(t, e.sendCode("alice"), 200, "")
	r := e.sendCode("alice")
	expect(t, r, 429, "too_frequent")
	ra := r.json["retry_after"].(float64)
	if ra < 29 || ra > 30 || r.header.Get("Retry-After") == "" {
		t.Errorf("retry_after = %v, header %q", ra, r.header.Get("Retry-After"))
	}
	expect(t, e.sendCode("bob"), 200, "")
}

// T10：发码服务返回 500 → 502 send_failed，不进入冷却。
func TestT10SendFailed(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	e.send.setStatus(500)
	r := e.sendCode("alice")
	expect(t, r, 502, "send_failed")
	if r.json["upstream_status"].(float64) != 500 {
		t.Errorf("upstream_status = %v", r.json["upstream_status"])
	}
	e.send.setStatus(200)
	expect(t, e.sendCode("alice"), 200, "")
}

// T11：验证码错误 5 次 → 第 5 次 429，之后正确码 410。
func TestT11TooManyAttempts(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	expect(t, e.sendCode("alice"), 200, "")
	code := e.send.code("alice@example.com")
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for i := 1; i <= 4; i++ {
		r := e.validCode("alice", wrong)
		expect(t, r, 400, "invalid_code")
		if r.json["remaining_attempts"].(float64) != float64(5-i) {
			t.Errorf("remaining = %v", r.json["remaining_attempts"])
		}
	}
	expect(t, e.validCode("alice", wrong), 429, "too_many_attempts")
	expect(t, e.validCode("alice", code), 410, "code_expired")
}

// T12：验证码过期 → 410。
func TestT12Expired(t *testing.T) {
	e := newEnv(t, defaultUsers, "\tauthgate_code_ttl 1s")
	r := e.sendCode("alice")
	expect(t, r, 200, "")
	if r.json["expires_in"].(float64) != 1 {
		t.Errorf("expires_in = %v", r.json["expires_in"])
	}
	time.Sleep(1100 * time.Millisecond)
	expect(t, e.validCode("alice", e.send.code("alice@example.com")), 410, "code_expired")
}

// T13：同一验证码使用两次 → 第二次 410。
func TestT13CodeOnce(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	expect(t, e.sendCode("alice"), 200, "")
	code := e.send.code("alice@example.com")
	expect(t, e.validCode("alice", code), 200, "")
	expect(t, e.validCode("alice", code), 410, "code_expired")
}

// T22：重启 Caddy（未配置 secret）→ 原 token 仍有效。
func TestT22RestartKeepsToken(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	expect(t, e.sendCode("alice"), 200, "")
	r := e.validCode("alice", e.send.code("alice@example.com"))
	expect(t, r, 200, "")
	ck := "Cookie: authgate_token=" + cookieFrom(r).Value
	if err := caddy.Stop(); err != nil {
		t.Fatal(err)
	}
	e.load()
	r = e.get(e.url("web", "/"), ck)
	if r.status != 200 || !strings.Contains(r.body, "user=alice") {
		t.Fatalf("after restart: %d %s", r.status, r.body)
	}
}

// T23：篡改 token 中的用户名 → 401。
func TestT23TamperedToken(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	expect(t, e.sendCode("alice"), 200, "")
	r := e.validCode("alice", e.send.code("alice@example.com"))
	tok := cookieFrom(r).Value
	parts := strings.Split(tok, ".")
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var p map[string]any
	_ = json.Unmarshal(body, &p)
	p["u"] = "admin"
	nb, _ := json.Marshal(p)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(nb) + "." + parts[2]
	expect(t, e.get(e.url("api", "/authgate/me"), "Cookie: authgate_token="+forged), 401, "unauthorized")
	expect(t, e.get(e.url("web", "/"), "Cookie: authgate_token="+forged), 401, "")
}

func TestCodeSendErrors(t *testing.T) {
	e := newEnv(t, defaultUsers+"# root is admin without key\n", "")
	expect(t, e.sendCode("nobody"), 404, "user_not_found")
	expect(t, e.sendCode("bad user"), 400, "invalid_param")
	expect(t, e.sendCode("alice@other.com"), 400, "invalid_param")
	expect(t, e.get(e.url("auto", "/authgate/code/send?user=alice")), 405, "method_not_allowed")
	// 仅在管理员列表中的用户也可以登录
	expect(t, e.sendCode("root"), 200, "")
	r := e.validCode("root", e.send.code("root@example.com"))
	expect(t, r, 200, "")
	if r.json["is_admin"] != true {
		t.Errorf("valid = %v", r.json)
	}
	expect(t, e.post(e.url("auto", "/authgate/code/valid"), url.Values{"user": {"alice"}}), 400, "invalid_param")
}

func TestCodeSendRateLimit(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	for i := 0; i < 10; i++ {
		e.sendCode("nobody")
	}
	r := e.sendCode("alice")
	expect(t, r, 429, "rate_limited")
	if r.header.Get("Retry-After") == "" || r.json["retry_after"] == nil {
		t.Errorf("missing retry_after: %v", r.header)
	}
	for i := 0; i < 30; i++ {
		e.validCode("alice", "000000")
	}
	expect(t, e.validCode("alice", "000000"), 429, "rate_limited")
}

func TestCookieOptions(t *testing.T) {
	e := newEnv(t, defaultUsers, "\tauthgate_cookie_name sid\n\tauthgate_cookie_domain example.com\n\tauthgate_token_ttl 2h")
	expect(t, e.sendCode("alice"), 200, "")
	r := e.validCode("alice", e.send.code("alice@example.com"))
	expect(t, r, 200, "")
	var c *http.Cookie
	for _, x := range (&http.Response{Header: r.header}).Cookies() {
		if x.Name == "sid" {
			c = x
		}
	}
	if c == nil || c.Domain != "example.com" || c.MaxAge != 7200 {
		t.Fatalf("cookie = %+v", c)
	}
	r = e.get(e.url("web", "/"), "Cookie: sid="+c.Value)
	if r.status != 200 || !strings.Contains(r.body, "user=alice") {
		t.Fatalf("custom cookie: %d %s", r.status, r.body)
	}
}

// /authgate/ 管理页：未登录返回登录页，登录后返回管理页。
func TestManagePage(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	r := e.get(e.url("api", "/authgate"))
	if r.status != 301 || r.header.Get("Location") != "/authgate/" {
		t.Fatalf("redirect: %d %v", r.status, r.header)
	}
	r = e.get(e.url("api", "/authgate/"), "Accept: text/html")
	if r.status != 401 || !strings.Contains(r.body, "code/send") {
		t.Fatalf("unauthenticated: %d", r.status)
	}
	r = e.get(e.url("api", "/authgate/"), e.cookie("alice"))
	if r.status != 200 || !strings.Contains(r.body, "AuthGate 管理") || !strings.Contains(r.body, `var DOMAIN = "example.com";`) {
		t.Fatalf("manage page: %d", r.status)
	}
	if r.header.Get("Content-Security-Policy") != loginCSP || r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers = %v", r.header)
	}
	expect(t, e.do(nil, http.MethodPost, e.url("api", "/authgate/"), nil, e.cookie("alice")), 405, "method_not_allowed")
}
