package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/wjzhangq/caddy-authgate/internal/keygen"
)

const (
	k1 = "sk-68e8c80000000000000000a1"
	k2 = "sk-68e8c80000000000000000a2"
	k3 = "sk-68e8c80000000000000000a3"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "users.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestOpenCreatesFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "users.txt")
	s, err := Open(p, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("perm = %v", fi.Mode().Perm())
	}
	if s.Count() != 0 || s.Path() != p {
		t.Errorf("unexpected state")
	}
}

func TestParse(t *testing.T) {
	p := writeFile(t, "# comment\n\n"+k1+":Alice\n  "+k2+" : alice \nbadline\nshort:bob\n"+k3+":Bad User\nlegacy-key-123:carol\r\n")
	s, err := Open(p, []string{"Admin"}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := s.Lookup(k1); !ok || u != "alice" {
		t.Errorf("Lookup k1 = %q %v", u, ok)
	}
	if u, _ := s.Lookup(k2); u != "alice" {
		t.Errorf("Lookup k2 = %q", u)
	}
	if _, ok := s.Lookup(k3); ok {
		t.Errorf("invalid user line should be ignored")
	}
	if _, ok := s.Lookup("short"); ok {
		t.Errorf("short key should be ignored")
	}
	if u, _ := s.Lookup("legacy-key-123"); u != "carol" {
		t.Errorf("non-standard key should load, got %q", u)
	}
	if got := s.Keys("alice"); len(got) != 2 || got[0] != k1 {
		t.Errorf("Keys = %v", got)
	}
	if !s.Exists("admin") || !s.IsAdmin("admin") || s.Exists("nobody") {
		t.Errorf("Exists/IsAdmin wrong")
	}
	users := s.Users()
	want := []UserInfo{{"admin", true, 0}, {"alice", false, 2}, {"carol", false, 1}}
	if fmt.Sprint(users) != fmt.Sprint(want) {
		t.Errorf("Users = %v", users)
	}
}

func TestDuplicateKey(t *testing.T) {
	p := writeFile(t, k1+":a\n"+k1+":b\n")
	_, err := Open(p, nil, nil)
	var de *DuplicateKeyError
	if !errors.As(err, &de) || de.Line != 2 {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("msg = %v", err)
	}
}

func TestAddUserPreservesComments(t *testing.T) {
	p := writeFile(t, "# head\n"+k1+":alice\n\n# tail")
	s, err := Open(p, []string{"boss"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AddUser("Bad User"); !errors.Is(err, ErrInvalidUser) {
		t.Errorf("err = %v", err)
	}
	key, created, err := s.AddUser("alice")
	if err != nil || created || key != k1 {
		t.Errorf("existing AddUser = %q %v %v", key, created, err)
	}
	key, created, err = s.AddUser("Bob")
	if err != nil || !created || !keygen.IsStandard(key) {
		t.Fatalf("AddUser = %q %v %v", key, created, err)
	}
	// 管理员无 key 时新建
	bk, created, err := s.AddUser("boss")
	if err != nil || !created {
		t.Fatalf("admin AddUser = %v %v", created, err)
	}
	got := readFile(t, p)
	want := "# head\n" + k1 + ":alice\n\n# tail\n" + key + ":bob\n" + bk + ":boss\n"
	if got != want {
		t.Errorf("file =\n%s\nwant\n%s", got, want)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("perm = %v", fi.Mode().Perm())
	}
	// 重新打开内容一致
	s2, err := Open(p, nil, nil)
	if err != nil || s2.Count() != 3 {
		t.Fatalf("reopen: %v %d", err, s2.Count())
	}
}

func TestDeleteUser(t *testing.T) {
	p := writeFile(t, "#c\n"+k1+":alice\n"+k2+":bob\n"+k3+":alice\n")
	s, _ := Open(p, nil, nil)
	if _, err := s.DeleteUser("nobody"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v", err)
	}
	n, err := s.DeleteUser("alice")
	if err != nil || n != 2 {
		t.Fatalf("DeleteUser = %d %v", n, err)
	}
	if s.Exists("alice") {
		t.Errorf("alice should be gone")
	}
	if got := readFile(t, p); got != "#c\n"+k2+":bob\n" {
		t.Errorf("file = %q", got)
	}
}

func TestKeys(t *testing.T) {
	p := writeFile(t, k1+":alice\n"+k2+":boss\n")
	s, _ := Open(p, []string{"boss"}, nil)
	if _, err := s.AddKey("BAD USER", 0); !errors.Is(err, ErrInvalidUser) {
		t.Errorf("err = %v", err)
	}
	nk, err := s.AddKey("alice", 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddKey("alice", 2); !errors.Is(err, ErrKeyLimit) {
		t.Errorf("limit err = %v", err)
	}
	if err := s.DeleteKey("alice", k2); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("foreign key err = %v", err)
	}
	if err := s.DeleteKey("alice", ""); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("empty key err = %v", err)
	}
	if err := s.DeleteKey("alice", nk); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteKey("alice", k1); !errors.Is(err, ErrLastKey) {
		t.Errorf("last key err = %v", err)
	}
	// 管理员可删除最后一个 key
	if err := s.DeleteKey("boss", k2); err != nil {
		t.Errorf("admin delete last key: %v", err)
	}
	if !s.Exists("boss") {
		t.Errorf("admin without key should exist")
	}
}

func TestReload(t *testing.T) {
	p := writeFile(t, k1+":alice\n")
	s, _ := Open(p, nil, nil)
	if changed, err := s.Reload(); err != nil || changed {
		t.Fatalf("Reload unchanged = %v %v", changed, err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.WriteFile(p, []byte(k1+":alice\n"+k2+":bob\n"), 0o600)
	_ = os.Chtimes(p, future, future)
	if changed, err := s.Reload(); err != nil || !changed {
		t.Fatalf("Reload = %v %v", changed, err)
	}
	if u, _ := s.Lookup(k2); u != "bob" {
		t.Errorf("k2 not loaded")
	}
	// 解析失败保留旧数据
	_ = os.WriteFile(p, []byte(k1+":alice\n"+k1+":bob\n"), 0o600)
	future = future.Add(time.Second)
	_ = os.Chtimes(p, future, future)
	if _, err := s.Reload(); err == nil {
		t.Fatal("expected duplicate error")
	}
	if u, _ := s.Lookup(k2); u != "bob" {
		t.Errorf("old data should be kept")
	}
	// 变更前同步失败返回错误
	if _, _, err := s.AddUser("carol"); err == nil {
		t.Errorf("AddUser should fail while file is invalid")
	}
	if _, err := s.AddKey("bob", 0); err == nil {
		t.Errorf("AddKey should fail")
	}
	if _, err := s.DeleteUser("bob"); err == nil {
		t.Errorf("DeleteUser should fail")
	}
	if err := s.DeleteKey("bob", k2); err == nil {
		t.Errorf("DeleteKey should fail")
	}
	_ = os.Remove(p)
	if _, err := s.Reload(); err == nil {
		t.Errorf("missing file should error")
	}
}

func TestWatch(t *testing.T) {
	p := writeFile(t, k1+":alice\n")
	s, _ := Open(p, nil, zap.NewNop())
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { s.Watch(stop, 10*time.Millisecond); close(done) }()
	future := time.Now().Add(5 * time.Second)
	_ = os.WriteFile(p, []byte(k1+":alice\n"+k1+":dup\n"), 0o600)
	_ = os.Chtimes(p, future, future)
	time.Sleep(50 * time.Millisecond)
	_ = os.WriteFile(p, []byte(k2+":bob\n"), 0o600)
	future = future.Add(time.Second)
	_ = os.Chtimes(p, future, future)
	deadline := time.Now().Add(2 * time.Second)
	for !s.Exists("bob") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	<-done
	if !s.Exists("bob") || s.Exists("alice") {
		t.Errorf("watch did not reload")
	}
}

func TestConcurrent(t *testing.T) {
	p := writeFile(t, "# c\n")
	s, _ := Open(p, nil, nil)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := fmt.Sprintf("u%d", i)
			k, _, err := s.AddUser(u)
			if err != nil {
				t.Error(err)
				return
			}
			k2, err := s.AddKey(u, 0)
			if err != nil {
				t.Error(err)
				return
			}
			_ = s.DeleteKey(u, k)
			_, _ = s.Lookup(k2)
			_ = s.Users()
		}(i)
	}
	wg.Wait()
	s2, err := Open(p, nil, nil)
	if err != nil || s2.Count() != 20 || s.Count() != 20 {
		t.Fatalf("count = %d / %d err %v", s2.Count(), s.Count(), err)
	}
	if !strings.HasPrefix(readFile(t, p), "# c\n") {
		t.Errorf("comment lost")
	}
}

func TestValidators(t *testing.T) {
	if !ValidUser("a") || !ValidUser("a.b_c-1") || ValidUser("-a") || ValidUser("A") || ValidUser(strings.Repeat("a", 65)) {
		t.Errorf("ValidUser")
	}
	if ValidKey("1234567") || !ValidKey("12345678") || ValidKey("1234 5678") || ValidKey(strings.Repeat("a", 129)) || ValidKey("abcd:efgh") {
		t.Errorf("ValidKey")
	}
}

func TestWriteAtomicError(t *testing.T) {
	if err := writeAtomic(filepath.Join(t.TempDir(), "nodir", "x"), []byte("x")); err == nil {
		t.Errorf("expected error")
	}
}
