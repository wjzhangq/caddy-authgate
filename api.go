package authgate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/wjzhangq/caddy-authgate/internal/code"
	"github.com/wjzhangq/caddy-authgate/internal/keygen"
	"github.com/wjzhangq/caddy-authgate/internal/ratelimit"
	"github.com/wjzhangq/caddy-authgate/internal/store"
)

const maxBodySize = 64 << 10

// endpoint 描述一个 /authgate/* 接口。
type endpoint struct {
	auth    authLevel
	mutates bool     // 变更类接口：Cookie 认证时需通过 CSRF 校验
	methods []string // 允许的方法
	fn      func(h *Handler, w http.ResponseWriter, r *http.Request, c *apiCtx) error
}

type authLevel int

const (
	authNone authLevel = iota
	authUser
	authAdmin
)

var getPost = []string{http.MethodGet, http.MethodPost}

var endpoints = map[string]endpoint{
	"user/add":    {authAdmin, true, getPost, (*Handler).apiUserAdd},
	"user/delete": {authAdmin, true, getPost, (*Handler).apiUserDelete},
	"user/list":   {authAdmin, false, getPost, (*Handler).apiUserList},
	"key/list":    {authUser, false, getPost, (*Handler).apiKeyList},
	"key/add":     {authUser, true, getPost, (*Handler).apiKeyAdd},
	"key/delete":  {authUser, true, getPost, (*Handler).apiKeyDelete},
	"me":          {authUser, false, getPost, (*Handler).apiMe},
	"code/send":   {authNone, false, []string{http.MethodPost}, (*Handler).apiCodeSend},
	"code/valid":  {authNone, false, []string{http.MethodPost}, (*Handler).apiCodeValid},
	"logout":      {authNone, false, getPost, (*Handler).apiLogout},
}

// apiCtx 是单次接口调用的上下文。
type apiCtx struct {
	id     *identity
	params url.Values
	ip     string
}

// serveAPI 处理 /authgate/* 接口。
func (h *Handler) serveAPI(w http.ResponseWriter, r *http.Request) error {
	ep, ok := endpoints[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, apiPrefix), "/")]
	if !ok {
		return writeError(w, http.StatusNotFound, errNotFound, nil)
	}
	if !allowed(r.Method, ep.methods) {
		w.Header().Set("Allow", strings.Join(ep.methods, ", "))
		return writeError(w, http.StatusMethodNotAllowed, errMethodNotAllowed, nil)
	}
	c := &apiCtx{ip: clientIP(r)}

	if ep.auth != authNone {
		id, _, reason := h.authenticate(r, true)
		if reason == reasonRateLimited {
			return h.writeRateLimited(w, r)
		}
		if id == nil {
			return writeError(w, http.StatusUnauthorized, errUnauthorized, nil)
		}
		if ep.auth == authAdmin && !id.admin {
			return writeError(w, http.StatusForbidden, errForbidden, nil)
		}
		if ep.mutates && id.method == methodWeb && !csrfOK(r) {
			return writeError(w, http.StatusForbidden, errCSRF, nil)
		}
		c.id = id
	}

	params, err := readParams(r)
	if err != nil {
		return writeError(w, http.StatusBadRequest, errInvalidParam, nil)
	}
	c.params = params
	return ep.fn(h, w, r, c)
}

func allowed(method string, methods []string) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

// csrfOK 校验 Cookie 认证的变更请求：必须为 POST，且 Origin（缺省取 Referer）的 host 等于请求 Host。
func csrfOK(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	src := r.Header.Get("Origin")
	if src == "" || src == "null" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		return false
	}
	u, err := url.Parse(src)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// readParams 合并 query、form 与 JSON body 中的参数。
func readParams(r *http.Request) (url.Values, error) {
	params := url.Values{}
	for k, v := range r.URL.Query() {
		params[k] = v
	}
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
		return params, nil
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	body := http.MaxBytesReader(nil, r.Body, maxBodySize)
	switch ct {
	case "application/json":
		var m map[string]any
		dec := json.NewDecoder(body)
		if err := dec.Decode(&m); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		for k, v := range m {
			switch x := v.(type) {
			case string:
				params.Set(k, x)
			case float64, bool:
				params.Set(k, fmt.Sprint(x))
			}
		}
	case "application/x-www-form-urlencoded", "multipart/form-data":
		r.Body = body
		if err := r.ParseMultipartForm(maxBodySize); err != nil && !errors.Is(err, http.ErrNotMultipart) {
			return nil, err
		}
		for k, v := range r.PostForm {
			params[k] = v
		}
	}
	return params, nil
}

// userParam 读取并规范化 user 参数；输入完整邮箱时去掉匹配的域名后缀。
func (h *Handler) userParam(c *apiCtx) (string, bool) {
	u := store.NormalizeUser(c.params.Get("user"))
	if at := strings.LastIndexByte(u, '@'); at >= 0 {
		if u[at+1:] != h.core.Config().Domain {
			return "", false
		}
		u = u[:at]
	}
	return u, store.ValidUser(u)
}

func (h *Handler) storageError(w http.ResponseWriter, err error) error {
	h.logger.Error("authgate: failed to write user file", zap.String("path", h.core.users.Path()), zap.Error(err))
	return writeError(w, http.StatusInternalServerError, errStorage, nil)
}

func (h *Handler) audit(msg string, c *apiCtx, user, key string) {
	fields := []zap.Field{zap.String("operator", c.id.user), zap.String("user", user), zap.String("ip", c.ip)}
	if key != "" {
		fields = append(fields, zap.String("key", keygen.Mask(key)))
	}
	h.logger.Info(msg, fields...)
}

// user/add?user=
func (h *Handler) apiUserAdd(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	user, ok := h.userParam(c)
	if !ok {
		return writeError(w, http.StatusBadRequest, errInvalidParam, nil)
	}
	key, created, err := h.core.users.AddUser(user)
	if err != nil {
		return h.storageError(w, err)
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		h.audit("authgate: user added", c, user, key)
	}
	return writeJSON(w, status, map[string]any{"user": user, "key": key, "created": created})
}

// user/delete?user=
func (h *Handler) apiUserDelete(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	user, ok := h.userParam(c)
	if !ok {
		return writeError(w, http.StatusBadRequest, errInvalidParam, nil)
	}
	if user == c.id.user {
		return writeError(w, http.StatusConflict, errCannotDeleteSelf, nil)
	}
	if h.core.users.IsAdmin(user) {
		return writeError(w, http.StatusConflict, errUserIsAdmin, nil)
	}
	n, err := h.core.users.DeleteUser(user)
	if errors.Is(err, store.ErrUserNotFound) {
		return writeError(w, http.StatusNotFound, errUserNotFound, nil)
	}
	if err != nil {
		return h.storageError(w, err)
	}
	h.audit("authgate: user deleted", c, user, "")
	return writeJSON(w, http.StatusOK, map[string]any{"user": user, "deleted": true, "keys_removed": n})
}

// user/list
func (h *Handler) apiUserList(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	return writeJSON(w, http.StatusOK, map[string]any{"users": h.core.users.Users()})
}

type keyInfo struct {
	Key       string     `json:"key"`
	CreatedAt *time.Time `json:"created_at"`
}

// keyTarget 返回 key 接口操作的目标用户：未指定 user 时为当前用户；
// 指定其他用户时要求当前用户为管理员且目标用户存在。出错时已输出响应，返回 ok=false。
func (h *Handler) keyTarget(w http.ResponseWriter, c *apiCtx) (user string, ok bool, err error) {
	if strings.TrimSpace(c.params.Get("user")) == "" {
		return c.id.user, true, nil
	}
	user, valid := h.userParam(c)
	switch {
	case !valid:
		return "", false, writeError(w, http.StatusBadRequest, errInvalidParam, nil)
	case user == c.id.user:
		return user, true, nil
	case !c.id.admin:
		return "", false, writeError(w, http.StatusForbidden, errForbidden, nil)
	case !h.core.users.Exists(user):
		return "", false, writeError(w, http.StatusNotFound, errUserNotFound, nil)
	}
	return user, true, nil
}

// key/list[?user=]
func (h *Handler) apiKeyList(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	user, ok, err := h.keyTarget(w, c)
	if !ok {
		return err
	}
	keys := h.core.users.Keys(user)
	out := make([]keyInfo, 0, len(keys))
	for _, k := range keys {
		ki := keyInfo{Key: k}
		if t, ok := keygen.CreatedAt(k); ok {
			ki.CreatedAt = &t
		}
		out = append(out, ki)
	}
	return writeJSON(w, http.StatusOK, map[string]any{"user": user, "keys": out})
}

// key/add[?user=]
func (h *Handler) apiKeyAdd(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	user, ok, err := h.keyTarget(w, c)
	if !ok {
		return err
	}
	key, err := h.core.users.AddKey(user, h.core.Config().MaxKeys)
	if errors.Is(err, store.ErrKeyLimit) {
		return writeError(w, http.StatusConflict, errKeyLimit, map[string]any{"max_keys": h.core.Config().MaxKeys})
	}
	if err != nil {
		return h.storageError(w, err)
	}
	h.audit("authgate: key added", c, user, key)
	return writeJSON(w, http.StatusCreated, map[string]any{"user": user, "key": key})
}

// key/delete?key=[&user=]
func (h *Handler) apiKeyDelete(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	user, ok, err := h.keyTarget(w, c)
	if !ok {
		return err
	}
	key := strings.TrimSpace(c.params.Get("key"))
	if key == "" {
		return writeError(w, http.StatusBadRequest, errInvalidParam, nil)
	}
	err = h.core.users.DeleteKey(user, key)
	switch {
	case errors.Is(err, store.ErrKeyNotFound):
		return writeError(w, http.StatusNotFound, errKeyNotFound, nil)
	case errors.Is(err, store.ErrLastKey):
		return writeError(w, http.StatusConflict, errLastKey, nil)
	case err != nil:
		return h.storageError(w, err)
	}
	h.audit("authgate: key deleted", c, user, key)
	return writeJSON(w, http.StatusOK, map[string]any{"user": user, "key": key, "deleted": true})
}

// me
func (h *Handler) apiMe(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	var exp *time.Time
	if !c.id.exp.IsZero() {
		t := c.id.exp.UTC()
		exp = &t
	}
	return writeJSON(w, http.StatusOK, map[string]any{
		"user": c.id.user, "is_admin": c.id.admin, "method": c.id.method, "expires_at": exp,
	})
}

// rateLimited 按 IP 限流，被限流时输出 429 并返回 true。
func (h *Handler) rateLimited(w http.ResponseWriter, bucket string, c *apiCtx) (bool, error) {
	if ok, wait := h.core.limiter.Allow(bucket, c.ip); !ok {
		return true, writeError(w, http.StatusTooManyRequests, errRateLimited, map[string]any{"retry_after": seconds(wait)})
	}
	return false, nil
}

// code/send?user=
func (h *Handler) apiCodeSend(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	if limited, err := h.rateLimited(w, ratelimit.CodeSend, c); limited {
		return err
	}
	user, ok := h.userParam(c)
	if !ok {
		return writeError(w, http.StatusBadRequest, errInvalidParam, nil)
	}
	core := h.core
	cfg := core.Config()
	if !core.users.Exists(user) {
		h.logger.Warn("authgate: code send rejected", zap.String("user", user), zap.String("ip", c.ip), zap.String("reason", "user_not_found"))
		return writeError(w, http.StatusNotFound, errUserNotFound, nil)
	}
	now := time.Now()
	cd, wait, err := core.codes.Issue(user, now)
	if errors.Is(err, code.ErrTooFrequent) {
		return writeError(w, http.StatusTooManyRequests, errTooFrequent, map[string]any{"retry_after": seconds(wait)})
	}
	if err != nil {
		return err
	}
	email := user + "@" + cfg.Domain
	ttl := core.codes.TTL()
	status, err := core.mailer.Load().Send(r.Context(), email, cd, ttl)
	if err != nil {
		h.logger.Warn("authgate: code send failed", zap.String("user", user), zap.String("ip", c.ip),
			zap.Int("upstream_status", status), zap.Error(err))
		return writeError(w, http.StatusBadGateway, errSendFailed, map[string]any{"upstream_status": status})
	}
	core.codes.Commit(user, cd, now)
	h.logger.Info("authgate: code sent", zap.String("user", user), zap.String("ip", c.ip), zap.Int("upstream_status", status))
	return writeJSON(w, http.StatusOK, map[string]any{
		"user":         user,
		"email":        email,
		"expires_in":   seconds(ttl),
		"resend_after": seconds(core.codes.Interval()),
	})
}

// code/valid?user=&code=
func (h *Handler) apiCodeValid(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	if limited, err := h.rateLimited(w, ratelimit.CodeValid, c); limited {
		return err
	}
	user, ok := h.userParam(c)
	cd := strings.TrimSpace(c.params.Get("code"))
	if !ok || cd == "" {
		return writeError(w, http.StatusBadRequest, errInvalidParam, nil)
	}
	core := h.core
	fail := func(reason string) {
		h.logger.Warn("authgate: login failed", zap.String("user", user), zap.String("ip", c.ip),
			zap.String("method", methodWeb), zap.String("reason", reason))
	}
	remaining, err := core.codes.Verify(user, cd, time.Now())
	switch {
	case errors.Is(err, code.ErrInvalid):
		fail(errInvalidCode)
		return writeError(w, http.StatusBadRequest, errInvalidCode, map[string]any{"remaining_attempts": remaining})
	case errors.Is(err, code.ErrTooManyAttempts):
		fail(errTooManyAttempts)
		return writeError(w, http.StatusTooManyRequests, errTooManyAttempts, nil)
	case err != nil:
		fail(errCodeExpired)
		return writeError(w, http.StatusGone, errCodeExpired, nil)
	}
	if !core.users.Exists(user) {
		fail(errUserNotFound)
		return writeError(w, http.StatusGone, errCodeExpired, nil)
	}

	cfg := core.Config()
	ttl := time.Duration(cfg.TokenTTL)
	tok, _ := core.signer.Load().Sign(user, ttl)
	http.SetCookie(w, h.cookie(r, tok, seconds(ttl)))
	admin := core.users.IsAdmin(user)
	h.logger.Info("authgate: login succeeded", zap.String("user", user), zap.String("ip", c.ip), zap.String("method", methodWeb))
	return writeJSON(w, http.StatusOK, map[string]any{"user": user, "is_admin": admin, "expires_in": seconds(ttl)})
}

// logout
func (h *Handler) apiLogout(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	http.SetCookie(w, h.cookie(r, "", -1))
	if r.Method == http.MethodGet && acceptsHTML(r) {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, "/", http.StatusFound)
		return nil
	}
	return writeJSON(w, http.StatusOK, map[string]any{"logout": true})
}

// cookie 构造 AuthGate Cookie；maxAge<0 表示删除。
func (h *Handler) cookie(r *http.Request, value string, maxAge int) *http.Cookie {
	cfg := h.core.Config()
	return &http.Cookie{
		Name:     cfg.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   cfg.CookieDomain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	}
}
