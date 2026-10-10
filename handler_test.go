package authgate

import (
	"strings"
	"testing"
	"time"
)

func bearer(k string) string { return "Authorization: Bearer " + k }

// T02：curl 访问 auto 站点，无凭证 → 401 JSON + WWW-Authenticate。
func TestT02AutoNoCredentials(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	r := e.get(e.url("auto", "/"))
	expect(t, r, 401, "unauthorized")
	if r.header.Get("WWW-Authenticate") != `Bearer realm="authgate"` {
		t.Errorf("WWW-Authenticate = %q", r.header.Get("WWW-Authenticate"))
	}
	if r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", r.header.Get("Cache-Control"))
	}
	if r.json["message"] == "" {
		t.Errorf("missing message")
	}
}

// 未认证响应判定（4.5）。
func TestUnauthenticatedDecision(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	html := "Accept: text/html,application/xhtml+xml"
	cases := []struct {
		site, method string
		hdr          []string
		page         bool
	}{
		{"api", "GET", []string{html}, false},
		{"web", "GET", []string{html, "Authorization: Bearer nope"}, false},
		{"web", "GET", nil, true},
		{"web", "POST", nil, true},
		{"auto", "GET", []string{html, "X-Requested-With: XMLHttpRequest"}, false},
		{"auto", "GET", []string{html, "Authorization: Basic eDp5"}, false},
		{"auto", "GET", []string{html}, true},
		{"auto", "HEAD", []string{html}, true},
		{"auto", "POST", []string{html}, false},
		{"auto", "GET", []string{"Accept: application/json"}, false},
	}
	for _, c := range cases {
		r := e.do(nil, c.method, e.url(c.site, "/x"), nil, c.hdr...)
		if r.status != 401 {
			t.Errorf("%v: status %d", c, r.status)
		}
		isPage := strings.HasPrefix(r.header.Get("Content-Type"), "text/html")
		if isPage != c.page {
			t.Errorf("%v: page=%v, content-type %q", c, isPage, r.header.Get("Content-Type"))
		}
		if !c.page && r.header.Get("WWW-Authenticate") == "" {
			t.Errorf("%v: missing WWW-Authenticate", c)
		}
	}
}

// T03：api 站点仅带有效 Cookie → 401 JSON。
func TestT03APISiteRejectsCookie(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	tok, _ := e.signer().Sign("alice", time.Hour)
	expect(t, e.get(e.url("api", "/"), "Cookie: authgate_token="+tok, "Accept: text/html"), 401, "unauthorized")
	// 同一 Cookie 在 web 站点有效
	r := e.get(e.url("web", "/"), "Cookie: authgate_token="+tok)
	if r.status != 200 || !strings.Contains(r.body, "user=alice ") || !strings.Contains(r.body, "method=web") {
		t.Fatalf("web cookie: %d %s", r.status, r.body)
	}
}

// T04：有效 Bearer 访问任意站点 → 通过，后端收到 X-Auth-User、X-Is-Admin。
func TestT04BearerAllSites(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	for _, site := range []string{"auto", "web", "api"} {
		r := e.get(e.url(site, "/"), bearer(aliceKey))
		if r.status != 200 || !strings.Contains(r.body, "user=alice admin=false method=api") {
			t.Errorf("%s: %d %s", site, r.status, r.body)
		}
		r = e.get(e.url(site, "/"), "Authorization: bearer "+adminKey)
		if r.status != 200 || !strings.Contains(r.body, "user=admin admin=true method=api") {
			t.Errorf("%s admin: %d %s", site, r.status, r.body)
		}
	}
}

// T05：无效 Bearer + 有效 Cookie 访问 web 站点 → 401 JSON。
func TestT05InvalidBearerWithCookie(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	tok, _ := e.signer().Sign("alice", time.Hour)
	r := e.get(e.url("web", "/"), "Authorization: Bearer sk-invalid-key-000", "Cookie: authgate_token="+tok, "Accept: text/html")
	expect(t, r, 401, "unauthorized")
}

// T06：伪造 X-Auth-User 访问 bypass 路径 → 后端收不到该 header。
func TestT06ForgedHeaderStripped(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	for _, p := range []string{"/healthz", "/public/a.css"} {
		r := e.get(e.url("auto", p), "X-Auth-User: admin", "X-Is-Admin: true", "X-Auth-Method: api")
		if r.status != 200 || !strings.Contains(r.body, "user= admin= method= ") {
			t.Errorf("%s: %d %s", p, r.status, r.body)
		}
	}
	// 认证通过时伪造值被覆盖
	r := e.get(e.url("auto", "/"), bearer(aliceKey), "X-Is-Admin: true")
	if !strings.Contains(r.body, "admin=false") {
		t.Errorf("forged admin passed: %s", r.body)
	}
}

// T07：后端收到的请求不含 Authorization 与 AuthGate Cookie。
func TestT07CredentialsStripped(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	r := e.get(e.url("auto", "/"), bearer(aliceKey))
	if !strings.Contains(r.body, "authz= ") {
		t.Errorf("Authorization leaked: %s", r.body)
	}
	tok, _ := e.signer().Sign("alice", time.Hour)
	r = e.get(e.url("web", "/"), "Cookie: other=1; authgate_token="+tok)
	if r.status != 200 || !strings.Contains(r.body, "cookie=[other=1]") {
		t.Errorf("cookie leaked: %d %s", r.status, r.body)
	}
}

// T24：站点含 respond 指令时认证先于 respond 执行。
func TestT24AuthBeforeRespond(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	r := e.get(e.url("auto", "/"))
	if r.status != 401 || strings.Contains(r.body, "user=") {
		t.Fatalf("respond ran before auth: %d %s", r.status, r.body)
	}
}

// 删除用户后 Cookie 失效；过期与篡改的 token 无效。
func TestCookieValidation(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	s := e.signer()
	tok, _ := s.Sign("ghost", time.Hour)
	expect(t, e.get(e.url("web", "/"), "Cookie: authgate_token="+tok, "X-Requested-With: XMLHttpRequest"), 401, "")
	s.Now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	tok, _ = s.Sign("alice", time.Hour)
	expect(t, e.get(e.url("web", "/"), "Cookie: authgate_token="+tok), 401, "")
}
