package authgate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/wjzhangq/caddy-authgate/internal/keygen"
)

// BenchmarkServeHTTPBearer100k 测量 10 万 key 下 Bearer 认证的完整处理器延迟。
func BenchmarkServeHTTPBearer100k(b *testing.B) {
	var sb strings.Builder
	keys := make([]string, 100000)
	for i := range keys {
		keys[i] = keygen.New(time.Now())
		fmt.Fprintf(&sb, "%s:user%d\n", keys[i], i/5)
	}
	file := filepath.Join(b.TempDir(), "users.txt")
	if err := os.WriteFile(file, []byte(sb.String()), 0o600); err != nil {
		b.Fatal(err)
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: b.Context()})
	defer cancel()
	h := &Handler{Global: GlobalConfig{File: file, SendCodeURL: "http://127.0.0.1:1"}}
	if err := h.Provision(ctx); err != nil {
		b.Fatal(err)
	}
	defer func() { _ = h.Cleanup() }()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Authorization", "Bearer "+keys[i%len(keys)])
			w := httptest.NewRecorder()
			if err := h.ServeHTTP(w, r, next); err != nil || r.Header.Get(hdrUser) == "" {
				b.Fatalf("auth failed: %v %d", err, w.Code)
			}
			i += 7919
		}
	})
}
