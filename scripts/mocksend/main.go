// Command mocksend 模拟 AuthGate 发码服务：接收 POST 并在终端打印邮箱与验证码。
//
// 额外提供两个调试接口，便于端到端测试：
//
//	GET  /last?email=x   返回该邮箱最近一次收到的验证码（纯文本，未收到时 404）
//	POST /status?code=N  设置后续发码请求的响应状态码（默认 200）
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"sync"
)

var codeRe = regexp.MustCompile(`<b>(\d{6})</b>`)

func main() {
	addr := flag.String("addr", "127.0.0.1:9999", "listen address")
	flag.Parse()

	var (
		mu     sync.Mutex
		status = http.StatusOK
		last   = map[string]string{}
	)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /last", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		c, ok := last[r.URL.Query().Get("email")]
		mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, c)
	})
	mux.HandleFunc("POST /status", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.URL.Query().Get("code"))
		if err != nil || n < 100 || n > 599 {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		mu.Lock()
		status = n
		mu.Unlock()
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email   string `json:"email"`
			Subject string `json:"subject"`
			HTML    string `json:"html"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		code := ""
		if m := codeRe.FindStringSubmatch(req.HTML); m != nil {
			code = m[1]
		}
		mu.Lock()
		st := status
		if st/100 == 2 {
			last[req.Email] = code
		}
		mu.Unlock()
		log.Printf("email=%s code=%s subject=%q status=%d auth=%q", req.Email, code, req.Subject, st, r.Header.Get("Authorization"))
		w.WriteHeader(st)
		fmt.Fprintln(w, `{"ok":true}`)
	})

	log.Printf("mocksend listening on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
