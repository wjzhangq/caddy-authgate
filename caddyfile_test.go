package authgate

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

// adaptHandler 将 Caddyfile 转为 JSON 并取出第一个 authgate handler。
func adaptHandler(t *testing.T, cfg string) (Handler, error) {
	t.Helper()
	js, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(cfg), nil)
	if err != nil {
		return Handler{}, err
	}
	var doc struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Handle []json.RawMessage `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(js, &doc); err != nil {
		t.Fatal(err)
	}
	var find func(raw json.RawMessage) *Handler
	find = func(raw json.RawMessage) *Handler {
		var m map[string]json.RawMessage
		_ = json.Unmarshal(raw, &m)
		if string(m["handler"]) == `"authgate"` {
			var h Handler
			if err := json.Unmarshal(raw, &h); err != nil {
				t.Fatal(err)
			}
			return &h
		}
		var sub struct {
			Routes []struct {
				Handle []json.RawMessage `json:"handle"`
			} `json:"routes"`
		}
		_ = json.Unmarshal(raw, &sub)
		for _, r := range sub.Routes {
			for _, hh := range r.Handle {
				if h := find(hh); h != nil {
					return h
				}
			}
		}
		return nil
	}
	for _, srv := range doc.Apps.HTTP.Servers {
		for _, r := range srv.Routes {
			for _, raw := range r.Handle {
				if h := find(raw); h != nil {
					return *h, nil
				}
			}
		}
	}
	t.Fatalf("authgate handler not found in %s", js)
	return Handler{}, nil
}

func TestCaddyfileGlobalOptions(t *testing.T) {
	h, err := adaptHandler(t, `{
	authgate_file            /etc/caddy/users.txt
	authgate_token_ttl       2h
	authgate_admin           alice bob
	authgate_admin           carol,dave
	authgate_domain          example.com
	authgate_sendcode_url    https://test.com/send
	authgate_sendcode_header Authorization "Bearer {env.MAIL_TOKEN}"
	authgate_sendcode_header X-Other 1
	authgate_secret          {env.AUTHGATE_SECRET}
	authgate_code_ttl        10m
	authgate_code_interval   1m
	authgate_cookie_name     sid
	authgate_cookie_domain   .example.com
	authgate_max_keys        5
}
:8080 {
	authgate api {
		bypass /healthz /static/*
		bypass /favicon.ico
		strip_credentials off
	}
	respond ok
}`)
	if err != nil {
		t.Fatal(err)
	}
	g := h.Global
	if g.File != "/etc/caddy/users.txt" || time.Duration(g.TokenTTL) != 2*time.Hour ||
		strings.Join(g.Admins, " ") != "alice bob carol dave" || g.Domain != "example.com" ||
		g.SendCodeURL != "https://test.com/send" || g.SendCodeHeader["Authorization"] != "Bearer {env.MAIL_TOKEN}" ||
		g.SendCodeHeader["X-Other"] != "1" || g.Secret != "{env.AUTHGATE_SECRET}" ||
		time.Duration(g.CodeTTL) != 10*time.Minute || time.Duration(g.CodeInterval) != time.Minute ||
		g.CookieName != "sid" || g.CookieDomain != ".example.com" || g.MaxKeys != 5 {
		t.Errorf("global = %+v", g)
	}
	if h.Mode != "api" || strings.Join(h.Bypass, " ") != "/healthz /static/* /favicon.ico" || h.StripCredentials == nil || *h.StripCredentials {
		t.Errorf("handler = %+v", h)
	}
}

func TestCaddyfileDirectiveForms(t *testing.T) {
	h, err := adaptHandler(t, "{\n\tauthgate_file u.txt\n\tauthgate_sendcode_url http://x\n}\n:8080 {\n\tauthgate\n\trespond ok\n}")
	if err != nil || h.Mode != "" || h.StripCredentials != nil {
		t.Fatalf("plain: %+v %v", h, err)
	}
	h, err = adaptHandler(t, ":8080 {\n\tauthgate {\n\t\tmode web\n\t\tstrip_credentials on\n\t}\n}")
	if err != nil || h.Mode != "web" || !*h.StripCredentials {
		t.Fatalf("block: %+v %v", h, err)
	}
}

func TestCaddyfileErrors(t *testing.T) {
	bad := []string{
		":80 {\n\tauthgate bogus\n}",
		":80 {\n\tauthgate api web\n}",
		":80 {\n\tauthgate {\n\t\tmode\n\t}\n}",
		":80 {\n\tauthgate {\n\t\tmode nope\n\t}\n}",
		":80 {\n\tauthgate {\n\t\tmode api web\n\t}\n}",
		":80 {\n\tauthgate {\n\t\tbypass\n\t}\n}",
		":80 {\n\tauthgate {\n\t\tstrip_credentials\n\t}\n}",
		":80 {\n\tauthgate {\n\t\tstrip_credentials maybe\n\t}\n}",
		":80 {\n\tauthgate {\n\t\tstrip_credentials on off\n\t}\n}",
		":80 {\n\tauthgate {\n\t\tunknown\n\t}\n}",
		"{\n\tauthgate_file\n}\n:80 {\n}",
		"{\n\tauthgate_file a b\n}\n:80 {\n}",
		"{\n\tauthgate_file a\n\tauthgate_file b\n}\n:80 {\n}",
		"{\n\tauthgate_token_ttl forever\n}\n:80 {\n}",
		"{\n\tauthgate_max_keys -1\n}\n:80 {\n}",
		"{\n\tauthgate_admin\n}\n:80 {\n}",
		"{\n\tauthgate_sendcode_header X\n}\n:80 {\n}",
		"{\n\tauthgate_domain a {\n\t\tx\n\t}\n}\n:80 {\n}",
	}
	for _, cfg := range bad {
		if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(cfg), nil); err == nil {
			t.Errorf("expected error for:\n%s", cfg)
		}
	}
}

func TestResolveAndValidate(t *testing.T) {
	t.Setenv("AG_SECRET", strings.Repeat("s", 32))
	t.Setenv("AG_ADMINS", "Root,Ops")
	g := GlobalConfig{
		File:           "users.txt",
		SendCodeURL:    "http://send",
		Secret:         "{env.AG_SECRET}",
		Admins:         []string{"{env.AG_ADMINS}", "Alice"},
		Domain:         "@Example.COM",
		SendCodeHeader: map[string]string{"A": "{env.AG_SECRET}"},
	}.resolve(caddy.NewReplacer())
	if !strings.HasPrefix(g.File, "/") || g.Secret != strings.Repeat("s", 32) ||
		strings.Join(g.Admins, ",") != "root,ops,alice" || g.Domain != "example.com" ||
		g.SendCodeHeader["A"] != g.Secret || g.CookieName != defaultCookieName || g.MaxKeys != defaultMaxKeys ||
		time.Duration(g.TokenTTL) != defaultTokenTTL || time.Duration(g.CodeTTL) != defaultCodeTTL ||
		time.Duration(g.CodeInterval) != defaultCodeInterval {
		t.Fatalf("resolved = %+v", g)
	}
	if err := g.validate(); err != nil {
		t.Fatal(err)
	}
	if d := (GlobalConfig{}).resolve(caddy.NewReplacer()); d.Domain != defaultDomain {
		t.Errorf("default domain = %q", d.Domain)
	}

	bad := []GlobalConfig{
		{SendCodeURL: "x"},
		{File: "f"},
		{File: "f", SendCodeURL: "x", CodeInterval: caddy.Duration(10 * time.Second)},
		{File: "f", SendCodeURL: "x", Secret: "short"},
		{File: "f", SendCodeURL: "x", Admins: []string{"-bad"}},
	}
	for _, b := range bad {
		if err := b.resolve(caddy.NewReplacer()).validate(); err == nil {
			t.Errorf("expected error for %+v", b)
		}
	}
}

func TestProvisionErrors(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	cases := []Handler{
		{Mode: "bogus"},
		{Global: GlobalConfig{SendCodeURL: "x"}},
		{Global: GlobalConfig{File: dir + "/dup.txt", SendCodeURL: "x"}},
	}
	_ = writeTestFile(dir+"/dup.txt", adminKey+":a\n"+adminKey+":b\n")
	for _, h := range cases {
		if err := h.Provision(ctx); err == nil {
			t.Errorf("expected error for %+v", h)
			_ = h.Cleanup()
		}
	}
	var h Handler
	if err := h.Validate(); err == nil {
		t.Errorf("Validate on unprovisioned handler should fail")
	}
	if err := h.Cleanup(); err != nil {
		t.Errorf("Cleanup: %v", err)
	}
	if (&Handler{}).CaddyModule().ID != "http.handlers.authgate" {
		t.Errorf("module ID")
	}
}

func TestExampleCaddyfileAdapts(t *testing.T) {
	b, err := os.ReadFile("examples/Caddyfile")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt(b, nil); err != nil {
		t.Fatal(err)
	}
}
