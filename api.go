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

	"github.com/wjzhangq/caddy-authgate/internal/keygen"
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
		id, _, _ := h.authenticate(r, true)
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

// key/list
func (h *Handler) apiKeyList(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	keys := h.core.users.Keys(c.id.user)
	out := make([]keyInfo, 0, len(keys))
	for _, k := range keys {
		ki := keyInfo{Key: k}
		if t, ok := keygen.CreatedAt(k); ok {
			ki.CreatedAt = &t
		}
		out = append(out, ki)
	}
	return writeJSON(w, http.StatusOK, map[string]any{"user": c.id.user, "keys": out})
}

// key/add
func (h *Handler) apiKeyAdd(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	key, err := h.core.users.AddKey(c.id.user, h.core.Config().MaxKeys)
	if errors.Is(err, store.ErrKeyLimit) {
		return writeError(w, http.StatusConflict, errKeyLimit, map[string]any{"max_keys": h.core.Config().MaxKeys})
	}
	if err != nil {
		return h.storageError(w, err)
	}
	h.audit("authgate: key added", c, c.id.user, key)
	return writeJSON(w, http.StatusCreated, map[string]any{"user": c.id.user, "key": key})
}

// key/delete?key=
func (h *Handler) apiKeyDelete(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	key := strings.TrimSpace(c.params.Get("key"))
	if key == "" {
		return writeError(w, http.StatusBadRequest, errInvalidParam, nil)
	}
	err := h.core.users.DeleteKey(c.id.user, key)
	switch {
	case errors.Is(err, store.ErrKeyNotFound):
		return writeError(w, http.StatusNotFound, errKeyNotFound, nil)
	case errors.Is(err, store.ErrLastKey):
		return writeError(w, http.StatusConflict, errLastKey, nil)
	case err != nil:
		return h.storageError(w, err)
	}
	h.audit("authgate: key deleted", c, c.id.user, key)
	return writeJSON(w, http.StatusOK, map[string]any{"user": c.id.user, "key": key, "deleted": true})
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
