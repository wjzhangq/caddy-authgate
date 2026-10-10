package store

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wjzhangq/caddy-authgate/internal/keygen"
)

// genFile 生成包含 n 个 key（每用户 5 个）的用户文件。
func genFile(tb testing.TB, n int) (string, []string) {
	tb.Helper()
	var b strings.Builder
	keys := make([]string, n)
	now := time.Now()
	for i := range keys {
		keys[i] = keygen.New(now)
		fmt.Fprintf(&b, "%s:user%d\n", keys[i], i/5)
	}
	p := filepath.Join(tb.TempDir(), "users.txt")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		tb.Fatal(err)
	}
	return p, keys
}

// BenchmarkLookup100k 测量 10 万 key 下的认证查找延迟。
func BenchmarkLookup100k(b *testing.B) {
	p, keys := genFile(b, 100000)
	s, err := Open(p, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, ok := s.Lookup(keys[i%len(keys)]); !ok {
				b.Fatal("missing key")
			}
			i += 7919
		}
	})
}

// BenchmarkOpen100k 测量 10 万 key 的加载耗时与内存占用。
func BenchmarkOpen100k(b *testing.B) {
	p, _ := genFile(b, 100000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		s, err := Open(p, nil, nil)
		if err != nil {
			b.Fatal(err)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/(1<<20), "MiB-heap")
		runtime.KeepAlive(s)
	}
}

// BenchmarkAddKey100k 测量 10 万 key 下新增 key（整文件原子重写）的耗时。
func BenchmarkAddKey100k(b *testing.B) {
	p, _ := genFile(b, 100000)
	s, err := Open(p, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.AddKey("user1", 0); err != nil {
			b.Fatal(err)
		}
	}
}
