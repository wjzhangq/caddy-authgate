package authgate

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/wjzhangq/caddy-authgate/internal/ratelimit"
)

// 站点模式。
const (
	ModeAuto = "auto"
	ModeWeb  = "web"
	ModeAPI  = "api"
)

// 认证方式（X-Auth-Method）。
const (
	methodWeb = "web"
	methodAPI = "api"
)

// 注入上游的 header。
const (
	hdrUser   = "X-Auth-User"
	hdrAdmin  = "X-Is-Admin"
	hdrMethod = "X-Auth-Method"
)

const apiPrefix = "/authgate/"

// Handler 是 authgate HTTP 处理器。
type Handler struct {
	// Global 是全局配置，由 Caddyfile 全局选项注入。
	Global GlobalConfig `json:"global"`
	// Mode 为 auto、web 或 api，默认 auto。
	Mode string `json:"mode,omitempty"`
	// Bypass 中的路径无需认证。
	Bypass caddyhttp.MatchPath `json:"bypass,omitempty"`
	// StripCredentials 为 true（默认）时，转发上游前删除 Authorization 与 AuthGate Cookie。
	StripCredentials *bool `json:"strip_credentials,omitempty"`

	core    *Core
	coreKey string
	logger  *zap.Logger
}

// Provision 实现 caddy.Provisioner。
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.Mode == "" {
		h.Mode = ModeAuto
	}
	if !validMode(h.Mode) {
		return fmt.Errorf("invalid mode %q", h.Mode)
	}
	if h.StripCredentials == nil {
		v := true
		h.StripCredentials = &v
	}
	if len(h.Bypass) > 0 {
		if err := h.Bypass.Provision(ctx); err != nil {
			return err
		}
	}

	cfg := h.Global.resolve(caddy.NewReplacer())
	if err := cfg.validate(); err != nil {
		return err
	}
	v, loaded, err := pool.LoadOrNew(cfg.File, func() (caddy.Destructor, error) {
		return newCore(cfg, h.logger)
	})
	if err != nil {
		return err
	}
	core := v.(*Core)
	if loaded {
		if err := core.UpdateConfig(cfg); err != nil {
			_, _ = pool.Delete(cfg.File)
			return err
		}
	}
	h.core, h.coreKey = core, cfg.File
	return nil
}

// Validate 实现 caddy.Validator。
func (h *Handler) Validate() error {
	if h.core == nil {
		return fmt.Errorf("authgate: not provisioned")
	}
	return h.core.Config().validate()
}

// Cleanup 实现 caddy.CleanerUpper。
func (h *Handler) Cleanup() error {
	if h.coreKey != "" {
		_, err := pool.Delete(h.coreKey)
		h.core, h.coreKey = nil, ""
		return err
	}
	return nil
}

// identity 是一次认证的结果。
type identity struct {
	user   string
	admin  bool
	method string
	exp    time.Time // 仅 web 方式有值
}

// ServeHTTP 实现 caddyhttp.MiddlewareHandler。
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 1. 删除客户端伪造的身份 header
	r.Header.Del(hdrUser)
	r.Header.Del(hdrAdmin)
	r.Header.Del(hdrMethod)

	// 2. 内置接口
	if strings.HasPrefix(r.URL.Path, apiPrefix) {
		return h.serveAPI(w, r)
	}

	// 3. 免认证路径
	if len(h.Bypass) > 0 {
		ok, err := h.Bypass.MatchWithError(r)
		if err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		if ok {
			return next.ServeHTTP(w, r)
		}
	}

	// 4–5. 认证
	id, hasAuthz, reason := h.authenticate(r, h.Mode != ModeAPI)
	if reason == reasonRateLimited {
		return h.writeRateLimited(w, r)
	}
	if id != nil {
		r.Header.Set(hdrUser, id.user)
		r.Header.Set(hdrAdmin, fmt.Sprint(id.admin))
		r.Header.Set(hdrMethod, id.method)
		if *h.StripCredentials {
			h.stripCredentials(r)
		}
		return next.ServeHTTP(w, r)
	}
	if reason != "" {
		h.logger.Warn("authgate: authentication failed",
			zap.String("ip", clientIP(r)), zap.String("reason", reason), zap.String("path", r.URL.Path))
	}

	// 6. 未认证
	if h.wantsJSON(r, hasAuthz) {
		return writeError(w, http.StatusUnauthorized, errUnauthorized, nil)
	}
	return h.serveLoginPage(w, r)
}

const reasonRateLimited = "rate_limited"

// authenticate 提取并校验凭证。
// 携带 Authorization 时仅校验 Bearer key；否则在 allowCookie 时校验 Cookie token。
// reason 非空表示提交了凭证但校验失败；同一 IP 无效 Bearer 过多时 reason 为 rate_limited。
func (h *Handler) authenticate(r *http.Request, allowCookie bool) (id *identity, hasAuthz bool, reason string) {
	core := h.core
	if authz := r.Header.Get("Authorization"); authz != "" {
		ip := clientIP(r)
		if ok, _ := core.limiter.Check(ratelimit.BadBearer, ip); !ok {
			return nil, true, reasonRateLimited
		}
		scheme, cred, _ := strings.Cut(authz, " ")
		cred = strings.TrimSpace(cred)
		user, ok := "", false
		if strings.EqualFold(scheme, "Bearer") && cred != "" {
			user, ok = core.users.Lookup(cred)
		}
		if !ok {
			core.limiter.Allow(ratelimit.BadBearer, ip)
			if !strings.EqualFold(scheme, "Bearer") || cred == "" {
				return nil, true, "unsupported_authorization"
			}
			return nil, true, "invalid_key"
		}
		return &identity{user: user, admin: core.users.IsAdmin(user), method: methodAPI}, true, ""
	}
	if !allowCookie {
		return nil, false, ""
	}
	c, err := r.Cookie(core.Config().CookieName)
	if err != nil || c.Value == "" {
		return nil, false, ""
	}
	user, exp, err := core.signer.Load().Verify(c.Value, time.Now())
	if err != nil {
		return nil, false, "invalid_token"
	}
	if !core.users.Exists(user) {
		return nil, false, "user_not_found"
	}
	return &identity{user: user, admin: core.users.IsAdmin(user), method: methodWeb, exp: exp}, false, ""
}

// writeRateLimited 输出无效 Bearer 过多导致的 429。
func (h *Handler) writeRateLimited(w http.ResponseWriter, r *http.Request) error {
	_, wait := h.core.limiter.Check(ratelimit.BadBearer, clientIP(r))
	return writeError(w, http.StatusTooManyRequests, errRateLimited, map[string]any{"retry_after": seconds(wait)})
}

// stripCredentials 删除 Authorization header 与 AuthGate Cookie。
func (h *Handler) stripCredentials(r *http.Request) {
	r.Header.Del("Authorization")
	name := h.core.Config().CookieName
	cookies := r.Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == name {
			found = true
			break
		}
	}
	if !found {
		return
	}
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != name {
			r.AddCookie(c)
		}
	}
}

// wantsJSON 判定未认证时返回 401 JSON（true）还是登录页（false）。
func (h *Handler) wantsJSON(r *http.Request, hasAuthz bool) bool {
	switch h.Mode {
	case ModeAPI:
		return true
	case ModeWeb:
		return hasAuthz
	}
	if hasAuthz || strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && acceptsHTML(r) {
		return false
	}
	return true
}

func acceptsHTML(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

// clientIP 返回 Caddy 识别的客户端 IP。
func clientIP(r *http.Request) string {
	if ip, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
