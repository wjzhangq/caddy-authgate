// Package store 管理 AuthGate 用户文件：解析、索引、原子写入与热加载。
//
// 文件每行格式为 "<key>:<user>"，以第一个 ":" 分隔；以 "#" 开头的行为注释，
// 空行忽略。写入时保留注释与原有顺序，新行追加在末尾。
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"go.uber.org/zap"

	"github.com/wjzhangq/caddy-authgate/internal/keygen"
)

// 错误定义。
var (
	ErrInvalidUser  = errors.New("invalid user name")
	ErrUserNotFound = errors.New("user not found")
	ErrKeyNotFound  = errors.New("key not found")
	ErrLastKey      = errors.New("cannot delete the last key")
	ErrKeyLimit     = errors.New("key limit reached")
)

// DuplicateKeyError 表示用户文件中存在重复 key。
type DuplicateKeyError struct {
	Line int
}

func (e *DuplicateKeyError) Error() string {
	return fmt.Sprintf("duplicate key at line %d", e.Line)
}

var userRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidUser 报告 name 是否为合法用户名（需已转小写）。
func ValidUser(name string) bool {
	return userRe.MatchString(name)
}

// NormalizeUser 去除空白并转小写。
func NormalizeUser(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ValidKey 报告 key 是否满足基本规则：长度 8–128，不含空白与 ":"。
func ValidKey(key string) bool {
	if len(key) < 8 || len(key) > 128 {
		return false
	}
	for _, r := range key {
		if r == ':' || unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// UserInfo 描述一个用户。
type UserInfo struct {
	User     string `json:"user"`
	IsAdmin  bool   `json:"is_admin"`
	KeyCount int    `json:"key_count"`
}

// line 是用户文件中的一行。
type line struct {
	raw  string // 原始内容（注释、空行、非法行原样保留）
	key  string // 非空表示有效条目
	user string
}

type snapshot struct {
	lines  []line
	byKey  map[string]string
	byUser map[string][]string
}

// Store 是用户文件的内存视图。所有方法并发安全。
type Store struct {
	path string
	log  *zap.Logger

	mu     sync.RWMutex
	snap   snapshot
	admins map[string]bool
	mtime  time.Time
	size   int64

	now func() time.Time
}

// Open 打开（必要时创建）用户文件并加载。重复 key 会返回错误。
func Open(path string, admins []string, log *zap.Logger) (*Store, error) {
	if log == nil {
		log = zap.NewNop()
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	s := &Store{path: abs, log: log, now: time.Now}
	s.SetAdmins(admins)

	if _, err := os.Stat(abs); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if f != nil {
			_ = f.Close()
		}
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path 返回用户文件绝对路径。
func (s *Store) Path() string { return s.path }

func (s *Store) load() error {
	fi, err := os.Stat(s.path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	snap, err := s.parse(string(data))
	if err != nil {
		return err
	}
	s.snap = snap
	s.mtime = fi.ModTime()
	s.size = fi.Size()
	return nil
}

func (s *Store) parse(data string) (snapshot, error) {
	snap := snapshot{byKey: map[string]string{}, byUser: map[string][]string{}}
	data = strings.TrimSuffix(strings.ReplaceAll(data, "\r\n", "\n"), "\n")
	if data == "" {
		return snap, nil
	}
	for i, raw := range strings.Split(data, "\n") {
		ln := line{raw: raw}
		t := strings.TrimSpace(raw)
		if t != "" && !strings.HasPrefix(t, "#") {
			k, u, ok := strings.Cut(t, ":")
			k = strings.TrimSpace(k)
			u = NormalizeUser(u)
			switch {
			case !ok:
				s.log.Warn("authgate: ignoring malformed line", zap.String("path", s.path), zap.Int("line", i+1))
			case !ValidKey(k):
				s.log.Warn("authgate: ignoring line with invalid key", zap.String("path", s.path), zap.Int("line", i+1))
			case !ValidUser(u):
				s.log.Warn("authgate: ignoring line with invalid user", zap.String("path", s.path), zap.Int("line", i+1), zap.String("user", u))
			default:
				if _, dup := snap.byKey[k]; dup {
					return snapshot{}, &DuplicateKeyError{Line: i + 1}
				}
				if !keygen.IsStandard(k) {
					s.log.Warn("authgate: non-standard key format", zap.String("path", s.path), zap.Int("line", i+1), zap.String("user", u))
				}
				ln.key, ln.user = k, u
				snap.byKey[k] = u
				snap.byUser[u] = append(snap.byUser[u], k)
			}
		}
		snap.lines = append(snap.lines, ln)
	}
	return snap, nil
}

// Reload 在文件 mtime 或大小变化时重新加载。解析失败时保留旧数据并返回错误。
func (s *Store) Reload() (changed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reloadLocked()
}

func (s *Store) reloadLocked() (bool, error) {
	fi, err := os.Stat(s.path)
	if err != nil {
		return false, err
	}
	if fi.ModTime().Equal(s.mtime) && fi.Size() == s.size {
		return false, nil
	}
	if err := s.load(); err != nil {
		return false, err
	}
	return true, nil
}

// Watch 每隔 every 检查一次文件变化，直到 stop 关闭。
func (s *Store) Watch(stop <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			changed, err := s.Reload()
			if err != nil {
				s.log.Error("authgate: failed to reload user file", zap.String("path", s.path), zap.Error(err))
			} else if changed {
				s.log.Info("authgate: user file reloaded", zap.String("path", s.path))
			}
		}
	}
}

// SetAdmins 设置管理员列表。
func (s *Store) SetAdmins(admins []string) {
	m := make(map[string]bool, len(admins))
	for _, a := range admins {
		if a = NormalizeUser(a); a != "" {
			m[a] = true
		}
	}
	s.mu.Lock()
	s.admins = m
	s.mu.Unlock()
}

// IsAdmin 报告 user 是否在管理员列表中。
func (s *Store) IsAdmin(user string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.admins[user]
}

// Lookup 根据 key 查找用户。
func (s *Store) Lookup(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.snap.byKey[key]
	return u, ok
}

// Exists 报告用户是否存在：文件中有 key 或在管理员列表中。
func (s *Store) Exists(user string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.snap.byUser[user]) > 0 || s.admins[user]
}

// Keys 返回用户的全部 key（按文件顺序）。
func (s *Store) Keys(user string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.snap.byUser[user]...)
}

// Users 返回全部用户（含仅在管理员列表中的用户），按用户名排序。
func (s *Store) Users() []UserInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]UserInfo, 0, len(s.snap.byUser)+len(s.admins))
	for u, ks := range s.snap.byUser {
		out = append(out, UserInfo{User: u, IsAdmin: s.admins[u], KeyCount: len(ks)})
	}
	for a := range s.admins {
		if _, ok := s.snap.byUser[a]; !ok {
			out = append(out, UserInfo{User: a, IsAdmin: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

// Count 返回 key 总数。
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.snap.byKey)
}

// AddUser 添加用户并为其生成首个 key。用户已有 key 时返回第一个 key，created 为 false。
func (s *Store) AddUser(user string) (key string, created bool, err error) {
	user = NormalizeUser(user)
	if !ValidUser(user) {
		return "", false, ErrInvalidUser
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.syncLocked(); err != nil {
		return "", false, err
	}
	if ks := s.snap.byUser[user]; len(ks) > 0 {
		return ks[0], false, nil
	}
	key = s.newKeyLocked()
	if err := s.commitLocked(append(s.cloneLines(), line{raw: key + ":" + user, key: key, user: user})); err != nil {
		return "", false, err
	}
	return key, true, nil
}

// DeleteUser 删除用户的全部 key。
func (s *Store) DeleteUser(user string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.syncLocked(); err != nil {
		return 0, err
	}
	n := len(s.snap.byUser[user])
	if n == 0 {
		return 0, ErrUserNotFound
	}
	lines := make([]line, 0, len(s.snap.lines))
	for _, ln := range s.snap.lines {
		if ln.key != "" && ln.user == user {
			continue
		}
		lines = append(lines, ln)
	}
	if err := s.commitLocked(lines); err != nil {
		return 0, err
	}
	return n, nil
}

// AddKey 为用户新增一个 key；max>0 时限制每用户 key 数量。
func (s *Store) AddKey(user string, max int) (string, error) {
	if !ValidUser(user) {
		return "", ErrInvalidUser
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.syncLocked(); err != nil {
		return "", err
	}
	if max > 0 && len(s.snap.byUser[user]) >= max {
		return "", ErrKeyLimit
	}
	key := s.newKeyLocked()
	if err := s.commitLocked(append(s.cloneLines(), line{raw: key + ":" + user, key: key, user: user})); err != nil {
		return "", err
	}
	return key, nil
}

// DeleteKey 删除用户的某个 key。普通用户删除最后一个 key 返回 ErrLastKey。
func (s *Store) DeleteKey(user, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.syncLocked(); err != nil {
		return err
	}
	if s.snap.byKey[key] != user || key == "" {
		return ErrKeyNotFound
	}
	if len(s.snap.byUser[user]) == 1 && !s.admins[user] {
		return ErrLastKey
	}
	lines := make([]line, 0, len(s.snap.lines))
	for _, ln := range s.snap.lines {
		if ln.key == key {
			continue
		}
		lines = append(lines, ln)
	}
	return s.commitLocked(lines)
}

// syncLocked 在变更前确保内存数据与磁盘一致。
func (s *Store) syncLocked() error {
	_, err := s.reloadLocked()
	return err
}

func (s *Store) cloneLines() []line {
	return append(make([]line, 0, len(s.snap.lines)+1), s.snap.lines...)
}

func (s *Store) newKeyLocked() string {
	for {
		k := keygen.New(s.now())
		if _, dup := s.snap.byKey[k]; !dup {
			return k
		}
	}
}

// commitLocked 原子写入 lines 并更新内存索引。
func (s *Store) commitLocked(lines []line) error {
	var b strings.Builder
	for _, ln := range lines {
		b.WriteString(ln.raw)
		b.WriteByte('\n')
	}
	if err := writeAtomic(s.path, []byte(b.String())); err != nil {
		return err
	}
	snap := snapshot{lines: lines, byKey: map[string]string{}, byUser: map[string][]string{}}
	for _, ln := range lines {
		if ln.key != "" {
			snap.byKey[ln.key] = ln.user
			snap.byUser[ln.user] = append(snap.byUser[ln.user], ln.key)
		}
	}
	s.snap = snap
	if fi, err := os.Stat(s.path); err == nil {
		s.mtime, s.size = fi.ModTime(), fi.Size()
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
