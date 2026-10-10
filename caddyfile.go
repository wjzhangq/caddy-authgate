package authgate

import (
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// 全局选项名称。
const (
	optFile           = "authgate_file"
	optTokenTTL       = "authgate_token_ttl"
	optAdmin          = "authgate_admin"
	optDomain         = "authgate_domain"
	optSendCodeURL    = "authgate_sendcode_url"
	optSendCodeHeader = "authgate_sendcode_header"
	optSecret         = "authgate_secret"
	optCodeTTL        = "authgate_code_ttl"
	optCodeInterval   = "authgate_code_interval"
	optCookieName     = "authgate_cookie_name"
	optCookieDomain   = "authgate_cookie_domain"
	optMaxKeys        = "authgate_max_keys"
)

var globalOptionNames = []string{
	optFile, optTokenTTL, optAdmin, optDomain, optSendCodeURL, optSendCodeHeader,
	optSecret, optCodeTTL, optCodeInterval, optCookieName, optCookieDomain, optMaxKeys,
}

// parseGlobalOption 解析 authgate_* 全局选项。
//
// authgate_admin 与 authgate_sendcode_header 可出现多次并累加，其余选项只接受一个参数。
func parseGlobalOption(d *caddyfile.Dispenser, existing any) (any, error) {
	d.Next() // 选项名
	name := d.Val()
	args := d.RemainingArgs()
	if d.NextBlock(0) {
		return nil, d.Err("block is not supported")
	}

	switch name {
	case optAdmin:
		admins, _ := existing.([]string)
		for _, a := range args {
			for _, s := range strings.Split(a, ",") {
				if s = strings.TrimSpace(s); s != "" {
					admins = append(admins, s)
				}
			}
		}
		if len(args) == 0 {
			return nil, d.ArgErr()
		}
		return admins, nil

	case optSendCodeHeader:
		if len(args) != 2 {
			return nil, d.ArgErr()
		}
		hdr, _ := existing.(map[string]string)
		if hdr == nil {
			hdr = map[string]string{}
		}
		hdr[args[0]] = args[1]
		return hdr, nil
	}

	if len(args) != 1 {
		return nil, d.ArgErr()
	}
	if existing != nil {
		return nil, d.Errf("%s specified more than once", name)
	}
	v := args[0]
	switch name {
	case optTokenTTL, optCodeTTL, optCodeInterval:
		dur, err := caddy.ParseDuration(v)
		if err != nil {
			return nil, d.Errf("invalid duration %q: %v", v, err)
		}
		return caddy.Duration(dur), nil
	case optMaxKeys:
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, d.Errf("invalid %s %q", name, v)
		}
		return n, nil
	}
	return v, nil
}

// globalFromOptions 从 Caddyfile 全局选项构造 GlobalConfig。
func globalFromOptions(h httpcaddyfile.Helper) GlobalConfig {
	var g GlobalConfig
	str := func(name string) string { s, _ := h.Option(name).(string); return s }
	dur := func(name string) caddy.Duration { d, _ := h.Option(name).(caddy.Duration); return d }
	g.File = str(optFile)
	g.TokenTTL = dur(optTokenTTL)
	g.Admins, _ = h.Option(optAdmin).([]string)
	g.Domain = str(optDomain)
	g.SendCodeURL = str(optSendCodeURL)
	g.SendCodeHeader, _ = h.Option(optSendCodeHeader).(map[string]string)
	g.Secret = str(optSecret)
	g.CodeTTL = dur(optCodeTTL)
	g.CodeInterval = dur(optCodeInterval)
	g.CookieName = str(optCookieName)
	g.CookieDomain = str(optCookieDomain)
	g.MaxKeys, _ = h.Option(optMaxKeys).(int)
	return g
}

// parseDirective 解析站点指令：
//
//	authgate [auto|web|api] {
//	    mode              auto|web|api
//	    bypass            <paths...>
//	    strip_credentials on|off
//	}
func parseDirective(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	handler := &Handler{Global: globalFromOptions(h)}
	if err := handler.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return handler, nil
}

// UnmarshalCaddyfile 解析站点指令（不含全局选项）。
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // 指令名
	if d.NextArg() {
		h.Mode = d.Val()
		if !validMode(h.Mode) {
			return d.Errf("invalid mode %q", h.Mode)
		}
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "mode":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.Mode = d.Val()
			if !validMode(h.Mode) {
				return d.Errf("invalid mode %q", h.Mode)
			}
			if d.NextArg() {
				return d.ArgErr()
			}
		case "bypass":
			paths := d.RemainingArgs()
			if len(paths) == 0 {
				return d.ArgErr()
			}
			h.Bypass = append(h.Bypass, paths...)
		case "strip_credentials":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var v bool
			switch d.Val() {
			case "on", "true":
				v = true
			case "off", "false":
				v = false
			default:
				return d.Errf("strip_credentials must be on or off, got %q", d.Val())
			}
			h.StripCredentials = &v
			if d.NextArg() {
				return d.ArgErr()
			}
		default:
			return d.Errf("unknown subdirective %q", d.Val())
		}
	}
	return nil
}

func validMode(m string) bool {
	return m == ModeAuto || m == ModeWeb || m == ModeAPI
}

var _ caddyfile.Unmarshaler = (*Handler)(nil)
