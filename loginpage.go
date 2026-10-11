package authgate

import (
	"bytes"
	"html/template"
	"net/http"
	"time"

	"github.com/wjzhangq/caddy-authgate/loginpage"
)

const loginCSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'"

// serveLoginPage 在原 URL 返回 401 + 登录页。
func (h *Handler) serveLoginPage(w http.ResponseWriter, r *http.Request) error {
	return h.renderPage(w, loginpage.Template, http.StatusUnauthorized)
}

// apiManagePage 处理 /authgate/ 管理页：已登录返回管理页，未登录返回登录页（登录后刷新即进入管理页）。
func (h *Handler) apiManagePage(w http.ResponseWriter, r *http.Request, c *apiCtx) error {
	id, _, reason := h.authenticate(r, true)
	if reason == reasonRateLimited {
		return h.writeRateLimited(w, r)
	}
	if id == nil {
		return h.serveLoginPage(w, r)
	}
	return h.renderPage(w, loginpage.Manage, http.StatusOK)
}

func (h *Handler) renderPage(w http.ResponseWriter, tmpl *template.Template, status int) error {
	cfg := h.core.Config()
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, loginpage.Data{
		Domain:       cfg.Domain,
		CodeInterval: seconds(time.Duration(cfg.CodeInterval)),
	}); err != nil {
		return err
	}
	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Content-Security-Policy", loginCSP)
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_, err := w.Write(buf.Bytes())
	return err
}
