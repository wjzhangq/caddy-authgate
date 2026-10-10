// Package authgate 是一个 Caddy HTTP 处理器插件，提供邮箱验证码登录、
// Bearer key 认证、用户管理以及向上游注入身份 header 的能力。
package authgate

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("authgate", parseDirective)
	httpcaddyfile.RegisterDirectiveOrder("authgate", httpcaddyfile.After, "basic_auth")
	for _, name := range globalOptionNames {
		httpcaddyfile.RegisterGlobalOption(name, parseGlobalOption)
	}
}

// CaddyModule 返回模块信息。
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.authgate",
		New: func() caddy.Module { return new(Handler) },
	}
}
