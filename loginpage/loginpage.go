// Package loginpage 内置 AuthGate 登录页。
package loginpage

import (
	_ "embed"
	"html/template"
)

//go:embed login.html
var source string

// Template 是解析后的登录页模板。
var Template = template.Must(template.New("login").Parse(source))

// Data 是登录页模板变量。
type Data struct {
	Domain       string // 邮箱域名，如 example.com
	CodeInterval int    // 发送间隔（秒）
}
