package authgate

import "net/http"

// serveLoginPage 返回 401 + 登录页。
func (h *Handler) serveLoginPage(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_, err := w.Write([]byte("<!doctype html><title>Login</title><p>Login required</p>"))
	return err
}
