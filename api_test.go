package authgate

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wjzhangq/caddy-authgate/internal/keygen"
)

func (e *env) cookie(user string) string {
	tok, _ := e.signer().Sign(user, time.Hour)
	return "Cookie: authgate_token=" + tok
}

func (e *env) origin(site string) string {
	return "Origin: " + e.url(site, "")
}

// T14：普通用户调用 user/list → 403。
func TestT14NonAdminForbidden(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	expect(t, e.get(e.url("auto", "/authgate/user/list"), bearer(aliceKey)), 403, "forbidden")
	expect(t, e.get(e.url("auto", "/authgate/user/list")), 401, "unauthorized")
	r := e.get(e.url("auto", "/authgate/user/list"), bearer(adminKey))
	expect(t, r, 200, "")
	users := r.json["users"].([]any)
	var names []string
	for _, u := range users {
		m := u.(map[string]any)
		names = append(names, m["user"].(string))
		if m["user"] == "root" && (m["is_admin"] != true || m["key_count"].(float64) != 0) {
			t.Errorf("root = %v", m)
		}
	}
	if strings.Join(names, ",") != "admin,alice,bob,root" {
		t.Errorf("users = %v", names)
	}
}

// T15：管理员 Cookie + GET 调用 user/delete → 403 csrf_rejected。
func TestT15CookieCSRF(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	ck := e.cookie("admin")
	expect(t, e.get(e.url("auto", "/authgate/user/delete?user=bob"), ck, e.origin("auto")), 403, "csrf_rejected")
	// POST 但无 Origin/Referer
	expect(t, e.post(e.url("auto", "/authgate/user/delete"), url.Values{"user": {"bob"}}, ck), 403, "csrf_rejected")
	// POST 但 Origin 不匹配
	expect(t, e.post(e.url("auto", "/authgate/user/delete"), url.Values{"user": {"bob"}}, ck, "Origin: http://evil.example"), 403, "csrf_rejected")
	// Referer 匹配
	r := e.post(e.url("auto", "/authgate/key/add"), nil, e.cookie("alice"), "Referer: "+e.url("auto", "/page"))
	expect(t, r, 201, "")
	// 只读接口不受 CSRF 限制
	expect(t, e.get(e.url("api", "/authgate/user/list"), ck), 200, "")
	// 正确的 Cookie + POST + Origin
	r = e.post(e.url("auto", "/authgate/user/delete"), url.Values{"user": {"bob"}}, ck, e.origin("auto"))
	expect(t, r, 200, "")
	if r.json["keys_removed"].(float64) != 1 || r.json["deleted"] != true {
		t.Errorf("delete = %v", r.json)
	}
}

// T16：管理员 Bearer + GET user/add 已存在用户 → 200 created:false。
func TestT16AddExistingUser(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	r := e.get(e.url("api", "/authgate/user/add?user=alice"), bearer(adminKey))
	expect(t, r, 200, "")
	if r.json["created"] != false || r.json["key"] != aliceKey || r.json["user"] != "alice" {
		t.Errorf("add existing = %v", r.json)
	}
	r = e.get(e.url("api", "/authgate/user/add?user=Carol@example.com"), bearer(adminKey))
	expect(t, r, 201, "")
	key, _ := r.json["key"].(string)
	if r.json["created"] != true || r.json["user"] != "carol" || !keygen.IsStandard(key) {
		t.Fatalf("add new = %v", r.json)
	}
	// 新 key 立即可用
	if b := e.get(e.url("api", "/"), bearer(key)).body; !strings.Contains(b, "user=carol") {
		t.Errorf("new key not usable: %s", b)
	}
	// 无 key 的管理员 → 新建 201
	expect(t, e.get(e.url("api", "/authgate/user/add?user=root"), bearer(adminKey)), 201, "")
	// 非法参数
	for _, q := range []string{"", "?user=", "?user=-bad", "?user=x@other.com", "?user=" + strings.Repeat("a", 65)} {
		expect(t, e.get(e.url("api", "/authgate/user/add"+q), bearer(adminKey)), 400, "invalid_param")
	}
	// JSON body
	r = e.do(nil, http.MethodPost, e.url("api", "/authgate/user/add"), strings.NewReader(`{"user":"dave"}`), bearer(adminKey), "Content-Type: application/json")
	expect(t, r, 201, "")
	r = e.do(nil, http.MethodPost, e.url("api", "/authgate/user/add"), strings.NewReader(`{"user":`), bearer(adminKey), "Content-Type: application/json")
	expect(t, r, 400, "invalid_param")
	data, _ := os.ReadFile(e.file)
	if !strings.HasPrefix(string(data), "# test users\n") || !strings.Contains(string(data), ":dave\n") {
		t.Errorf("file = %s", data)
	}
}

// T17：删除用户后其 Cookie 与 key 均 401。
func TestT17DeletedUserLosesAccess(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	ck := e.cookie("bob")
	expect(t, e.get(e.url("api", "/authgate/me"), ck), 200, "")
	expect(t, e.get(e.url("api", "/authgate/user/delete?user=bob"), bearer(adminKey)), 200, "")
	expect(t, e.get(e.url("api", "/authgate/me"), ck), 401, "unauthorized")
	expect(t, e.get(e.url("api", "/authgate/me"), bearer(bobKey)), 401, "unauthorized")
	expect(t, e.get(e.url("web", "/"), ck), 401, "")
	expect(t, e.get(e.url("auto", "/"), bearer(bobKey)), 401, "unauthorized")
	expect(t, e.get(e.url("api", "/authgate/user/delete?user=bob"), bearer(adminKey)), 404, "user_not_found")
}

// T18：删除配置中的管理员 → 409 user_is_admin；删除自己 → 409 cannot_delete_self。
func TestT18DeleteAdmin(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	expect(t, e.get(e.url("api", "/authgate/user/delete?user=root"), bearer(adminKey)), 409, "user_is_admin")
	expect(t, e.get(e.url("api", "/authgate/user/delete?user=admin"), bearer(adminKey)), 409, "cannot_delete_self")
	expect(t, e.get(e.url("api", "/authgate/user/delete?user=-x"), bearer(adminKey)), 400, "invalid_param")
}

// T19：普通用户删除最后一个 key → 409 last_key。
func TestT19LastKey(t *testing.T) {
	e := newEnv(t, defaultUsers, "\tauthgate_max_keys 2")
	expect(t, e.get(e.url("api", "/authgate/key/delete?key="+aliceKey), bearer(aliceKey)), 409, "last_key")
	expect(t, e.get(e.url("api", "/authgate/key/delete?key="+bobKey), bearer(aliceKey)), 404, "key_not_found")
	expect(t, e.get(e.url("api", "/authgate/key/delete"), bearer(aliceKey)), 400, "invalid_param")

	r := e.get(e.url("api", "/authgate/key/add"), bearer(aliceKey))
	expect(t, r, 201, "")
	nk := r.json["key"].(string)
	expect(t, e.get(e.url("api", "/authgate/key/add"), bearer(aliceKey)), 409, "key_limit_reached")

	r = e.get(e.url("api", "/authgate/key/list"), bearer(nk))
	expect(t, r, 200, "")
	keys := r.json["keys"].([]any)
	if len(keys) != 2 || keys[1].(map[string]any)["key"] != nk || keys[1].(map[string]any)["created_at"] == nil {
		t.Fatalf("keys = %v", keys)
	}
	r = e.get(e.url("api", "/authgate/key/delete?key="+aliceKey), bearer(nk))
	expect(t, r, 200, "")
	if r.json["deleted"] != true || r.json["key"] != aliceKey {
		t.Errorf("delete = %v", r.json)
	}
	expect(t, e.get(e.url("api", "/"), bearer(aliceKey)), 401, "")
}

func TestMe(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	r := e.get(e.url("api", "/authgate/me"), bearer(adminKey))
	expect(t, r, 200, "")
	if r.json["user"] != "admin" || r.json["is_admin"] != true || r.json["method"] != "api" || r.json["expires_at"] != nil {
		t.Errorf("me bearer = %v", r.json)
	}
	// me 接受 Cookie，不受站点 mode 限制
	r = e.get(e.url("api", "/authgate/me"), e.cookie("alice"))
	expect(t, r, 200, "")
	if r.json["method"] != "web" || r.json["expires_at"] == nil || r.json["is_admin"] != false {
		t.Errorf("me cookie = %v", r.json)
	}
	if r.header.Get("Cache-Control") != "no-store" || r.header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("headers = %v", r.header)
	}
}

func TestAPIRouting(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	expect(t, e.get(e.url("auto", "/authgate/nope")), 404, "not_found")
	r := e.do(nil, http.MethodDelete, e.url("auto", "/authgate/me"), nil, bearer(adminKey))
	expect(t, r, 405, "method_not_allowed")
	if r.header.Get("Allow") == "" {
		t.Errorf("missing Allow")
	}
	// 尾部斜杠
	expect(t, e.get(e.url("auto", "/authgate/me/"), bearer(adminKey)), 200, "")
	// 无效 Bearer 不回退到 Cookie
	expect(t, e.get(e.url("auto", "/authgate/me"), "Authorization: Bearer bad-key-123", e.cookie("alice")), 401, "unauthorized")
	// multipart form
	body := "--X\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nerin\r\n--X--\r\n"
	r = e.do(nil, http.MethodPost, e.url("api", "/authgate/user/add"), strings.NewReader(body), bearer(adminKey), "Content-Type: multipart/form-data; boundary=X")
	expect(t, r, 201, "")
}

func TestStorageError(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	// 用户文件被替换为目录，读写均失败
	_ = os.Remove(e.file)
	if err := os.Mkdir(e.file, 0o700); err != nil {
		t.Fatal(err)
	}
	expect(t, e.get(e.url("api", "/authgate/user/add?user=zed"), bearer(adminKey)), 500, "storage_error")
}

func TestCSRFOK(t *testing.T) {
	mk := func(method, host string, hdr map[string]string) *http.Request {
		r, _ := http.NewRequest(method, "http://"+host+"/", nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	cases := []struct {
		r  *http.Request
		ok bool
	}{
		{mk("POST", "a.com", map[string]string{"Origin": "https://a.com"}), true},
		{mk("POST", "a.com:8443", map[string]string{"Origin": "https://a.com:8443"}), true},
		{mk("POST", "a.com", map[string]string{"Origin": "https://b.com"}), false},
		{mk("POST", "a.com", map[string]string{"Origin": "null", "Referer": "https://a.com/x"}), true},
		{mk("POST", "a.com", map[string]string{"Origin": "%%"}), false},
		{mk("POST", "a.com", nil), false},
		{mk("GET", "a.com", map[string]string{"Origin": "https://a.com"}), false},
	}
	for i, c := range cases {
		if got := csrfOK(c.r); got != c.ok {
			t.Errorf("case %d: %v", i, got)
		}
	}
}

// 管理员通过 user 参数管理他人 key；普通用户不能操作他人 key。
func TestAdminManagesOtherKeys(t *testing.T) {
	e := newEnv(t, defaultUsers, "")
	expect(t, e.get(e.url("api", "/authgate/key/list?user=bob"), bearer(aliceKey)), 403, "forbidden")
	expect(t, e.get(e.url("api", "/authgate/key/add?user=bob"), bearer(aliceKey)), 403, "forbidden")
	expect(t, e.get(e.url("api", "/authgate/key/delete?user=bob&key="+bobKey), bearer(aliceKey)), 403, "forbidden")
	// 指定自己等同于不指定
	r := e.get(e.url("api", "/authgate/key/list?user=alice"), bearer(aliceKey))
	expect(t, r, 200, "")

	expect(t, e.get(e.url("api", "/authgate/key/list?user=nobody"), bearer(adminKey)), 404, "user_not_found")
	expect(t, e.get(e.url("api", "/authgate/key/list?user=-bad"), bearer(adminKey)), 400, "invalid_param")
	r = e.get(e.url("api", "/authgate/key/list?user=bob"), bearer(adminKey))
	expect(t, r, 200, "")
	if r.json["user"] != "bob" || len(r.json["keys"].([]any)) != 1 {
		t.Fatalf("list = %v", r.json)
	}
	r = e.get(e.url("api", "/authgate/key/add?user=bob"), bearer(adminKey))
	expect(t, r, 201, "")
	nk := r.json["key"].(string)
	if r.json["user"] != "bob" {
		t.Errorf("add = %v", r.json)
	}
	if b := e.get(e.url("api", "/"), bearer(nk)).body; !strings.Contains(b, "user=bob") {
		t.Errorf("new key belongs to wrong user: %s", b)
	}
	expect(t, e.get(e.url("api", "/authgate/key/delete?user=bob&key="+aliceKey), bearer(adminKey)), 404, "key_not_found")
	expect(t, e.get(e.url("api", "/authgate/key/delete?user=bob&key="+bobKey), bearer(adminKey)), 200, "")
	expect(t, e.get(e.url("api", "/authgate/key/delete?user=bob&key="+nk), bearer(adminKey)), 409, "last_key")
	// 仅在管理员列表中的用户也可被添加 key
	expect(t, e.get(e.url("api", "/authgate/key/add?user=root"), bearer(adminKey)), 201, "")
	// Cookie 认证仍受 CSRF 约束
	expect(t, e.get(e.url("api", "/authgate/key/add?user=bob"), e.cookie("admin")), 403, "csrf_rejected")
}
