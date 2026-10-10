package authgate

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/wjzhangq/caddy-authgate/internal/code"
	"github.com/wjzhangq/caddy-authgate/internal/mailer"
	"github.com/wjzhangq/caddy-authgate/internal/ratelimit"
	"github.com/wjzhangq/caddy-authgate/internal/store"
	"github.com/wjzhangq/caddy-authgate/internal/token"
)

// 默认值。
const (
	defaultTokenTTL     = time.Hour
	defaultDomain       = "lenovo.com"
	defaultCodeTTL      = 5 * time.Minute
	defaultCodeInterval = 30 * time.Second
	minCodeInterval     = 30 * time.Second
	defaultCookieName   = "authgate_token"
	defaultMaxKeys      = 20
	minSecretLen        = 32

	reloadInterval = 5 * time.Second
	gcInterval     = time.Minute
)

// GlobalConfig 是所有站点共享的全局配置，来自 Caddyfile 的 authgate_* 全局选项。
type GlobalConfig struct {
	File           string            `json:"file"`
	TokenTTL       caddy.Duration    `json:"token_ttl,omitempty"`
	Admins         []string          `json:"admins,omitempty"`
	Domain         string            `json:"domain,omitempty"`
	SendCodeURL    string            `json:"sendcode_url"`
	SendCodeHeader map[string]string `json:"sendcode_header,omitempty"`
	Secret         string            `json:"secret,omitempty"`
	CodeTTL        caddy.Duration    `json:"code_ttl,omitempty"`
	CodeInterval   caddy.Duration    `json:"code_interval,omitempty"`
	CookieName     string            `json:"cookie_name,omitempty"`
	CookieDomain   string            `json:"cookie_domain,omitempty"`
	MaxKeys        int               `json:"max_keys,omitempty"`
}

// resolve 替换占位符（如 {env.X}）并填充默认值，返回新的配置。
func (g GlobalConfig) resolve(repl *caddy.Replacer) GlobalConfig {
	r := func(s string) string { return strings.TrimSpace(repl.ReplaceKnown(s, "")) }
	g.File = r(g.File)
	g.SendCodeURL = r(g.SendCodeURL)
	g.Secret = repl.ReplaceKnown(g.Secret, "")
	g.Domain = strings.TrimPrefix(strings.ToLower(r(g.Domain)), "@")
	g.CookieName = r(g.CookieName)
	g.CookieDomain = r(g.CookieDomain)
	admins := make([]string, 0, len(g.Admins))
	for _, a := range g.Admins {
		for _, s := range strings.Split(r(a), ",") {
			if s = store.NormalizeUser(s); s != "" {
				admins = append(admins, s)
			}
		}
	}
	g.Admins = admins
	if len(g.SendCodeHeader) > 0 {
		hdr := make(map[string]string, len(g.SendCodeHeader))
		for k, v := range g.SendCodeHeader {
			hdr[k] = repl.ReplaceKnown(v, "")
		}
		g.SendCodeHeader = hdr
	}

	if g.TokenTTL <= 0 {
		g.TokenTTL = caddy.Duration(defaultTokenTTL)
	}
	if g.Domain == "" {
		g.Domain = defaultDomain
	}
	if g.CodeTTL <= 0 {
		g.CodeTTL = caddy.Duration(defaultCodeTTL)
	}
	if g.CodeInterval == 0 {
		g.CodeInterval = caddy.Duration(defaultCodeInterval)
	}
	if g.CookieName == "" {
		g.CookieName = defaultCookieName
	}
	if g.MaxKeys <= 0 {
		g.MaxKeys = defaultMaxKeys
	}
	if g.File != "" {
		if abs, err := filepath.Abs(g.File); err == nil {
			g.File = abs
		}
	}
	return g
}

// validate 校验已 resolve 的配置。
func (g GlobalConfig) validate() error {
	if g.File == "" {
		return fmt.Errorf("authgate_file is required")
	}
	if g.SendCodeURL == "" {
		return fmt.Errorf("authgate_sendcode_url is required")
	}
	if time.Duration(g.CodeInterval) < minCodeInterval {
		return fmt.Errorf("authgate_code_interval must be at least %s", minCodeInterval)
	}
	if g.Secret != "" && len(g.Secret) < minSecretLen {
		return fmt.Errorf("authgate_secret must be at least %d bytes", minSecretLen)
	}
	for _, a := range g.Admins {
		if !store.ValidUser(a) {
			return fmt.Errorf("invalid admin user name %q", a)
		}
	}
	return nil
}

// pool 以用户文件绝对路径为键保存共享的 Core，reload 时状态得以保留。
var pool = caddy.NewUsagePool()

// Core 是同一用户文件对应的共享状态。
type Core struct {
	cfg     atomic.Pointer[GlobalConfig]
	users   *store.Store
	codes   *code.Store
	signer  atomic.Pointer[token.Signer]
	secret  []byte
	limiter *ratelimit.Limiter
	mailer  atomic.Pointer[mailer.Mailer]
	logger  *zap.Logger
	stop    chan struct{}
}

func newCore(cfg GlobalConfig, logger *zap.Logger) (*Core, error) {
	users, err := store.Open(cfg.File, cfg.Admins, logger)
	if err != nil {
		logger.Error("authgate: failed to load user file", zap.String("path", cfg.File), zap.Error(err))
		return nil, fmt.Errorf("loading user file %s: %w", cfg.File, err)
	}
	c := &Core{
		users:   users,
		codes:   code.New(time.Duration(cfg.CodeTTL), time.Duration(cfg.CodeInterval)),
		limiter: ratelimit.New(ratelimit.DefaultRules),
		logger:  logger,
		stop:    make(chan struct{}),
	}
	if err := c.UpdateConfig(cfg); err != nil {
		return nil, err
	}
	go users.Watch(c.stop, reloadInterval)
	go c.gcLoop()
	return c, nil
}

// UpdateConfig 应用可变配置：TTL、管理员列表、发码服务、签名密钥等。
func (c *Core) UpdateConfig(cfg GlobalConfig) error {
	secret, err := token.LoadSecret(cfg.Secret, cfg.File)
	if err != nil {
		return fmt.Errorf("loading secret: %w", err)
	}
	if c.signer.Load() == nil || !bytes.Equal(secret, c.secret) {
		c.secret = secret
		c.signer.Store(token.NewSigner(secret))
	}
	c.users.SetAdmins(cfg.Admins)
	c.codes.SetConfig(time.Duration(cfg.CodeTTL), time.Duration(cfg.CodeInterval))
	c.mailer.Store(mailer.New(cfg.SendCodeURL, cfg.SendCodeHeader))
	c.cfg.Store(&cfg)
	return nil
}

// Config 返回当前配置。
func (c *Core) Config() *GlobalConfig { return c.cfg.Load() }

func (c *Core) gcLoop() {
	t := time.NewTicker(gcInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case now := <-t.C:
			c.codes.GC(now)
			c.limiter.GC(now)
		}
	}
}

// Destruct 停止后台协程。实现 caddy.Destructor。
func (c *Core) Destruct() error {
	close(c.stop)
	return nil
}

var _ caddy.Destructor = (*Core)(nil)
