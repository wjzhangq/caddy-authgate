package authgate

import (
	"bytes"
	"net/http"
	"time"

	"github.com/wjzhangq/caddy-authgate/loginpage"
)

const loginCSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'"

// serveLoginPage 在原 URL 返回 401 + 登录页。
func (h *Handler) serveLoginPage(w http.ResponseWriter, r *http.Request) error {
	cfg := h.core.Config()
	var buf bytes.Buffer
	if err := loginpage.Template.Execute(&buf, loginpage.Data{
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
	w.WriteHeader(http.StatusUnauthorized)
	_, err := w.Write(buf.Bytes())
	return err
}
