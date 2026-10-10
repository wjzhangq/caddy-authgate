package authgate

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	"github.com/wjzhangq/caddy-authgate/internal/token"
)

// 测试中使用的 key。
const (
	adminKey = "sk-68e8c800aaaaaaaaaaaaaaaa"
	aliceKey = "sk-68e8c800bbbbbbbbbbbbbbbb"
	bobKey   = "sk-68e8c800cccccccccccccccc"
)

// mockSend 模拟发码服务，记录收到的验证码。
type mockSend struct {
	*httptest.Server
	mu     sync.Mutex
	status int
	codes  map[string]string
	header http.Header
	calls  int
}

func newMockSend(t *testing.T) *mockSend {
	m := &mockSend{status: http.StatusOK, codes: map[string]string{}}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Email, Subject, HTML string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		m.mu.Lock()
		defer m.mu.Unlock()
		m.calls++
		m.header = r.Header.Clone()
		if m.status/100 == 2 {
			i := strings.Index(req.HTML, "<b>")
			if i >= 0 {
				m.codes[req.Email] = req.HTML[i+3 : i+9]
			}
		}
		w.WriteHeader(m.status)
	}))
	t.Cleanup(m.Close)
	return m
}

func (m *mockSend) setStatus(s int) {
	m.mu.Lock()
	m.status = s
	m.mu.Unlock()
}

func (m *mockSend) code(email string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.codes[email]
}

// env 是一个运行中的 Caddy 测试环境。
type env struct {
	t        *testing.T
	dir      string
	file     string
	send     *mockSend
	ports    map[string]int // 站点名 → 端口
	extraGlb string
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// newEnv 启动包含 auto / web / api 三个站点的 Caddy。
func newEnv(t *testing.T, users string, extraGlobal string) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{
		t:        t,
		dir:      dir,
		file:     filepath.Join(dir, "users.txt"),
		send:     newMockSend(t),
		ports:    map[string]int{"auto": freePort(t), "web": freePort(t), "api": freePort(t)},
		extraGlb: extraGlobal,
	}
	if err := os.WriteFile(e.file, []byte(users), 0o600); err != nil {
		t.Fatal(err)
	}
	e.load()
	t.Cleanup(func() { _ = caddy.Stop() })
	return e
}

const echo = `respond "user={http.request.header.X-Auth-User} admin={http.request.header.X-Is-Admin} method={http.request.header.X-Auth-Method} authz={http.request.header.Authorization} cookie=[{http.request.header.Cookie}]"`

func (e *env) caddyfile() string {
	return fmt.Sprintf(`{
	admin off
	auto_https off
	persist_config off
	log {
		output discard
	}
	authgate_file %s
	authgate_sendcode_url %s
	authgate_sendcode_header X-Mail-Token "{env.AUTHGATE_TEST_MAIL_TOKEN}"
	authgate_admin admin, root
	authgate_domain example.com
	%s
}
http://127.0.0.1:%d {
	authgate {
		bypass /healthz /public/*
	}
	%s
}
http://127.0.0.1:%d {
	authgate web
	%s
}
http://127.0.0.1:%d {
	authgate {
		mode api
	}
	%s
}
`, e.file, e.send.URL, e.extraGlb, e.ports["auto"], echo, e.ports["web"], echo, e.ports["api"], echo)
}

// load 加载（或重新加载）配置。
func (e *env) load() {
	e.t.Helper()
	e.t.Setenv("AUTHGATE_TEST_MAIL_TOKEN", "mail-secret")
	adapter := caddyconfig.GetAdapter("caddyfile")
	js, _, err := adapter.Adapt([]byte(e.caddyfile()), nil)
	if err != nil {
		e.t.Fatalf("adapt: %v", err)
	}
	if err := caddy.Load(js, true); err != nil {
		e.t.Fatalf("load: %v", err)
	}
}

func (e *env) url(site, path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", e.ports[site], path)
}

// signer 返回与 Caddy 使用相同密钥的签名器。
func (e *env) signer() *token.Signer {
	secret, err := token.LoadSecret("", e.file)
	if err != nil {
		e.t.Fatal(err)
	}
	return token.NewSigner(secret)
}

type resp struct {
	status int
	header http.Header
	body   string
	json   map[string]any
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// do 发送请求。hdr 为 "Name: value" 形式。
func (e *env) do(client *http.Client, method, u string, body io.Reader, hdr ...string) resp {
	e.t.Helper()
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, h := range hdr {
		k, v, _ := strings.Cut(h, ":")
		req.Header.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	if client == nil {
		client = noRedirect
	}
	res, err := client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	r := resp{status: res.StatusCode, header: res.Header, body: string(b)}
	if strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
		_ = json.Unmarshal(b, &r.json)
	}
	return r
}

func (e *env) get(u string, hdr ...string) resp { return e.do(nil, http.MethodGet, u, nil, hdr...) }

func (e *env) post(u string, form url.Values, hdr ...string) resp {
	hdr = append(hdr, "Content-Type: application/x-www-form-urlencoded")
	return e.do(nil, http.MethodPost, u, strings.NewReader(form.Encode()), hdr...)
}

func newJar(t *testing.T) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, CheckRedirect: noRedirect.CheckRedirect}
}

func expect(t *testing.T, r resp, status int, errCode string) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d; body = %s", r.status, status, r.body)
	}
	if errCode != "" && r.json["error"] != errCode {
		t.Fatalf("error = %v, want %s; body = %s", r.json["error"], errCode, r.body)
	}
}

const defaultUsers = "# test users\n" + adminKey + ":admin\n" + aliceKey + ":alice\n" + bobKey + ":bob\n"

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
