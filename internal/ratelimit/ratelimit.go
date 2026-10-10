// Package ratelimit 提供按 bucket + IP 的令牌桶限流。
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// 内置 bucket 名称。
const (
	CodeSend    = "code_send"
	CodeValid   = "code_valid"
	BadBearer   = "bad_bearer"
	idleTimeout = time.Minute
)

// DefaultRules 是 AuthGate 使用的默认限流规则（每分钟次数）。
var DefaultRules = map[string]int{
	CodeSend:  10,
	CodeValid: 30,
	BadBearer: 60,
}

type entry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// Limiter 是按 bucket+IP 的限流器。并发安全。
type Limiter struct {
	rules map[string]int
	mu    sync.Mutex
	m     map[string]*entry
	// Now 返回当前时间，测试时可替换。
	Now func() time.Time
}

// New 创建 Limiter。rules 为 bucket → 每分钟允许次数，未配置的 bucket 不限流。
func New(rules map[string]int) *Limiter {
	r := make(map[string]int, len(rules))
	for k, v := range rules {
		r[k] = v
	}
	return &Limiter{rules: r, m: map[string]*entry{}, Now: time.Now}
}

// Allow 消耗一个令牌。被限流时返回 false 及需等待的时间。
func (l *Limiter) Allow(bucket, ip string) (bool, time.Duration) {
	return l.allowAt(bucket, ip, l.Now(), true)
}

// Check 判断当前是否会被限流，但不消耗令牌。
func (l *Limiter) Check(bucket, ip string) (bool, time.Duration) {
	return l.allowAt(bucket, ip, l.Now(), false)
}

func (l *Limiter) allowAt(bucket, ip string, now time.Time, consume bool) (bool, time.Duration) {
	n, ok := l.rules[bucket]
	if !ok || n <= 0 {
		return true, 0
	}
	k := bucket + "|" + ip
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[k]
	if e == nil {
		if !consume {
			return true, 0
		}
		e = &entry{lim: rate.NewLimiter(rate.Every(time.Minute/time.Duration(n)), n)}
		l.m[k] = e
	}
	if !consume {
		if e.lim.TokensAt(now) >= 1 {
			return true, 0
		}
		r := e.lim.ReserveN(now, 1)
		d := r.DelayFrom(now)
		r.CancelAt(now)
		return false, roundUp(d)
	}
	e.lastSeen = now
	r := e.lim.ReserveN(now, 1)
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, roundUp(d)
	}
	return true, 0
}

func roundUp(d time.Duration) time.Duration {
	if r := d % time.Second; r != 0 {
		d += time.Second - r
	}
	return d
}

// GC 清理空闲超过一分钟（令牌已回满）的桶。
func (l *Limiter) GC(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, e := range l.m {
		if now.Sub(e.lastSeen) >= idleTimeout {
			delete(l.m, k)
		}
	}
}

// Len 返回当前桶数量。
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}
