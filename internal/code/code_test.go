package code

import (
	"errors"
	"regexp"
	"testing"
	"time"
)

var t0 = time.Unix(1760000000, 0)

func TestIssueFormatAndCooldown(t *testing.T) {
	c := New(5*time.Minute, 30*time.Second)
	re := regexp.MustCompile(`^\d{6}$`)
	for i := 0; i < 50; i++ {
		code, wait, err := c.Issue("alice", t0)
		if err != nil || wait != 0 || !re.MatchString(code) {
			t.Fatalf("Issue = %q %v %v", code, wait, err)
		}
	}
	// 未 Commit 时不进入冷却（发送失败场景）
	code, _, _ := c.Issue("alice", t0)
	c.Commit("alice", code, t0)
	_, wait, err := c.Issue("alice", t0.Add(10*time.Second))
	if !errors.Is(err, ErrTooFrequent) || wait != 20*time.Second {
		t.Fatalf("cooldown: %v %v", wait, err)
	}
	if _, _, err := c.Issue("alice", t0.Add(30*time.Second)); err != nil {
		t.Fatalf("after interval: %v", err)
	}
	if _, _, err := c.Issue("bob", t0); err != nil {
		t.Fatalf("other user: %v", err)
	}
	if c.TTL() != 5*time.Minute || c.Interval() != 30*time.Second {
		t.Errorf("config getters")
	}
}

func TestResendInvalidatesOld(t *testing.T) {
	c := New(5*time.Minute, 30*time.Second)
	c.Commit("alice", "111111", t0)
	c.Commit("alice", "222222", t0.Add(31*time.Second))
	if _, err := c.Verify("alice", "111111", t0.Add(32*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Errorf("old code: %v", err)
	}
	if _, err := c.Verify("alice", "222222", t0.Add(32*time.Second)); err != nil {
		t.Errorf("new code: %v", err)
	}
}

func TestVerifyOnce(t *testing.T) {
	c := New(5*time.Minute, 30*time.Second)
	c.Commit("alice", "123456", t0)
	if _, err := c.Verify("alice", "123456", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify("alice", "123456", t0); !errors.Is(err, ErrExpired) {
		t.Errorf("second use: %v", err)
	}
}

func TestVerifyAttempts(t *testing.T) {
	c := New(5*time.Minute, 30*time.Second)
	c.Commit("alice", "123456", t0)
	for i := 1; i < MaxAttempts; i++ {
		rem, err := c.Verify("alice", "000000", t0)
		if !errors.Is(err, ErrInvalid) || rem != MaxAttempts-i {
			t.Fatalf("attempt %d: %d %v", i, rem, err)
		}
	}
	if _, err := c.Verify("alice", "000000", t0); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("5th: %v", err)
	}
	if _, err := c.Verify("alice", "123456", t0); !errors.Is(err, ErrExpired) {
		t.Fatalf("after lock: %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	c := New(5*time.Minute, 30*time.Second)
	c.Commit("alice", "123456", t0)
	if _, err := c.Verify("alice", "123456", t0.Add(5*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := c.Verify("nobody", "123456", t0); !errors.Is(err, ErrExpired) {
		t.Fatalf("missing: %v", err)
	}
}

func TestGCAndSetConfig(t *testing.T) {
	c := New(5*time.Minute, 30*time.Second)
	c.Commit("alice", "123456", t0)
	c.Commit("bob", "123456", t0.Add(4*time.Minute))
	c.GC(t0.Add(time.Minute))
	if codes, cds := c.Len(); codes != 2 || cds != 1 {
		t.Fatalf("after first GC: %d %d", codes, cds)
	}
	c.GC(t0.Add(6 * time.Minute))
	if codes, cds := c.Len(); codes != 1 || cds != 0 {
		t.Fatalf("after second GC: %d %d", codes, cds)
	}
	c.SetConfig(time.Minute, time.Hour)
	c.Commit("carol", "1", t0)
	if _, wait, _ := c.Issue("carol", t0); wait != time.Hour {
		t.Errorf("interval not updated: %v", wait)
	}
}
