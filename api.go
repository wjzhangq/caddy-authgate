package authgate

import "net/http"

// serveAPI 处理 /authgate/* 接口。
func (h *Handler) serveAPI(w http.ResponseWriter, r *http.Request) error {
	return writeError(w, http.StatusNotFound, errNotFound, nil)
}
