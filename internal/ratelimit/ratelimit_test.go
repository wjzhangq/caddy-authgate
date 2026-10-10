package ratelimit

import (
	"testing"
	"time"
)

func TestAllow(t *testing.T) {
	now := time.Unix(1760000000, 0)
	l := New(map[string]int{"b": 10})
	l.Now = func() time.Time { return now }
	for i := 0; i < 10; i++ {
		if ok, _ := l.Allow("b", "1.1.1.1"); !ok {
			t.Fatalf("request %d denied", i)
		}
	}
	ok, wait := l.Allow("b", "1.1.1.1")
	if ok || wait != 6*time.Second {
		t.Fatalf("11th: %v %v", ok, wait)
	}
	if ok, _ := l.Allow("b", "2.2.2.2"); !ok {
		t.Errorf("other IP denied")
	}
	// 被拒绝的请求不消耗令牌
	now = now.Add(6 * time.Second)
	if ok, _ := l.Allow("b", "1.1.1.1"); !ok {
		t.Errorf("after refill denied")
	}
	if ok, _ := l.Allow("b", "1.1.1.1"); ok {
		t.Errorf("should be denied again")
	}
	if ok, _ := l.Allow("unknown", "1.1.1.1"); !ok {
		t.Errorf("unconfigured bucket limited")
	}
}

func TestRetryAfterRounding(t *testing.T) {
	now := time.Unix(1760000000, 0)
	l := New(map[string]int{"b": 1})
	l.Now = func() time.Time { return now }
	l.Allow("b", "ip")
	now = now.Add(500 * time.Millisecond)
	if _, wait := l.Allow("b", "ip"); wait != 60*time.Second {
		t.Errorf("wait = %v", wait)
	}
	now = now.Add(59 * time.Second)
	if _, wait := l.Allow("b", "ip"); wait != time.Second {
		t.Errorf("wait = %v", wait)
	}
}

func TestCheck(t *testing.T) {
	now := time.Unix(1760000000, 0)
	l := New(map[string]int{"b": 2})
	l.Now = func() time.Time { return now }
	if ok, _ := l.Check("b", "ip"); !ok || l.Len() != 0 {
		t.Fatalf("check on fresh bucket")
	}
	l.Allow("b", "ip")
	if ok, _ := l.Check("b", "ip"); !ok {
		t.Fatalf("check with 1 token left")
	}
	l.Allow("b", "ip")
	ok, wait := l.Check("b", "ip")
	if ok || wait != 30*time.Second {
		t.Fatalf("check exhausted: %v %v", ok, wait)
	}
	if ok, _ := l.Check("b", "ip"); ok {
		t.Fatalf("check must not consume or refill")
	}
}

func TestGC(t *testing.T) {
	now := time.Unix(1760000000, 0)
	l := New(DefaultRules)
	l.Now = func() time.Time { return now }
	l.Allow(CodeSend, "a")
	now = now.Add(30 * time.Second)
	l.Allow(CodeValid, "b")
	l.GC(now.Add(40 * time.Second))
	if l.Len() != 1 {
		t.Fatalf("Len = %d", l.Len())
	}
	l.GC(now.Add(time.Minute))
	if l.Len() != 0 {
		t.Fatalf("Len = %d", l.Len())
	}
}
