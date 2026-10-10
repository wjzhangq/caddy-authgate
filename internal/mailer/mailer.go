// Package mailer 调用外部发码服务（sendcode_url）发送验证码邮件。
package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"
)

// Timeout 是调用发码服务的超时时间。
const Timeout = 10 * time.Second

// Subject 是验证码邮件标题。
const Subject = "登录验证码"

var tmpl = template.Must(template.New("mail").Parse(
	`<p>您的登录验证码为 <b>{{.Code}}</b>，{{.Minutes}} 分钟内有效。</p>
<p>如非本人操作，请忽略此邮件。</p>`))

// Request 是发送到 sendcode_url 的 JSON 请求体。
type Request struct {
	Email   string `json:"email"`
	Subject string `json:"subject"`
	HTML    string `json:"html"`
}

// UpstreamError 表示发码服务返回了非 2xx 状态码。
type UpstreamError struct {
	Status int
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("sendcode upstream returned status %d", e.Status)
}

// Mailer 调用发码服务。
type Mailer struct {
	URL    string
	Header map[string]string
	Client *http.Client
}

// New 创建 Mailer。
func New(url string, header map[string]string) *Mailer {
	return &Mailer{URL: url, Header: header, Client: &http.Client{Timeout: Timeout}}
}

// Minutes 返回 ttl 对应的分钟数（向上取整，至少 1）。
func Minutes(ttl time.Duration) int {
	m := int((ttl + time.Minute - 1) / time.Minute)
	if m < 1 {
		m = 1
	}
	return m
}

// Render 渲染邮件 HTML。
func Render(code string, ttl time.Duration) (string, error) {
	var b bytes.Buffer
	err := tmpl.Execute(&b, struct {
		Code    string
		Minutes int
	}{code, Minutes(ttl)})
	return b.String(), err
}

// Send 发送验证码。返回上游状态码（网络错误时为 0）。
func (m *Mailer) Send(ctx context.Context, email, code string, ttl time.Duration) (int, error) {
	html, err := Render(code, ttl)
	if err != nil {
		return 0, err
	}
	body, err := json.Marshal(Request{Email: email, Subject: Subject, HTML: html})
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	for k, v := range m.Header {
		req.Header.Set(k, v)
	}
	client := m.Client
	if client == nil {
		client = &http.Client{Timeout: Timeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, &UpstreamError{Status: resp.StatusCode}
	}
	return resp.StatusCode, nil
}
