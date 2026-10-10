// Package code 管理一次性邮箱验证码：生成、发送冷却、校验与尝试次数。
package code

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// MaxAttempts 是单个验证码允许的错误次数上限。
const MaxAttempts = 5

// 错误定义。
var (
	ErrTooFrequent     = errors.New("code requested too frequently")
	ErrExpired         = errors.New("code expired or not found")
	ErrInvalid         = errors.New("invalid code")
	ErrTooManyAttempts = errors.New("too many attempts")
)

type entry struct {
	code     string
	expires  time.Time
	attempts int
}

// Store 保存验证码与发送冷却状态。并发安全。
type Store struct {
	mu       sync.Mutex
	ttl      time.Duration
	interval time.Duration
	codes    map[string]*entry
	lastSent map[string]time.Time
}

// New 创建 Store。
func New(ttl, interval time.Duration) *Store {
	return &Store{
		ttl:      ttl,
		interval: interval,
		codes:    map[string]*entry{},
		lastSent: map[string]time.Time{},
	}
}

// SetConfig 更新有效期与发送间隔（reload 时调用）。
func (c *Store) SetConfig(ttl, interval time.Duration) {
	c.mu.Lock()
	c.ttl, c.interval = ttl, interval
	c.mu.Unlock()
}

// TTL 返回验证码有效期。
func (c *Store) TTL() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ttl
}

// Interval 返回发送间隔。
func (c *Store) Interval() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.interval
}

// Issue 为 user 生成新验证码。处于冷却期时返回 ErrTooFrequent 及剩余等待时间。
// 生成的验证码需在发送成功后调用 Commit 才会生效。
func (c *Store) Issue(user string, now time.Time) (string, time.Duration, error) {
	c.mu.Lock()
	last, ok := c.lastSent[user]
	interval := c.interval
	c.mu.Unlock()
	if ok {
		if wait := last.Add(interval).Sub(now); wait > 0 {
			return "", wait, ErrTooFrequent
		}
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%06d", n.Int64()), 0, nil
}

// Commit 保存已发送成功的验证码并开始冷却，旧验证码随之失效。
func (c *Store) Commit(user, code string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.codes[user] = &entry{code: code, expires: now.Add(c.ttl)}
	c.lastSent[user] = now
}

// Verify 校验验证码。成功后验证码作废。
// 错误时返回 ErrInvalid 与剩余尝试次数；达到上限返回 ErrTooManyAttempts 并作废；
// 不存在或过期返回 ErrExpired。
func (c *Store) Verify(user, code string, now time.Time) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.codes[user]
	if !ok {
		return 0, ErrExpired
	}
	if !now.Before(e.expires) {
		delete(c.codes, user)
		return 0, ErrExpired
	}
	if subtle.ConstantTimeCompare([]byte(e.code), []byte(code)) == 1 {
		delete(c.codes, user)
		return 0, nil
	}
	e.attempts++
	remaining := MaxAttempts - e.attempts
	if remaining <= 0 {
		delete(c.codes, user)
		return 0, ErrTooManyAttempts
	}
	return remaining, ErrInvalid
}

// GC 清理过期验证码与已结束的冷却记录。
func (c *Store) GC(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for u, e := range c.codes {
		if !now.Before(e.expires) {
			delete(c.codes, u)
		}
	}
	for u, t := range c.lastSent {
		if !now.Before(t.Add(c.interval)) {
			delete(c.lastSent, u)
		}
	}
}

// Len 返回当前保存的验证码与冷却记录数量（用于测试与监控）。
func (c *Store) Len() (codes, cooldowns int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.codes), len(c.lastSent)
}
