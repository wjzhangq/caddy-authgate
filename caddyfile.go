package authgate

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

var globalOptionNames = []string{}

func parseGlobalOption(d *caddyfile.Dispenser, existing any) (any, error) {
	return nil, d.Err("not implemented")
}

func parseDirective(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return new(Handler), nil
}
