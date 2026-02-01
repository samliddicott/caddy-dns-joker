package caddydnsjoker

import (
	"context"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
	"github.com/samliddicott/libdns-joker"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Provider{})
}

// Provider implements libdns interfaces for Joker DNS via libdns-joker.
type Provider struct {
	// Authentication (exactly one method required)
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	APIToken string `json:"api_token,omitempty"`

	// Optional override
	Endpoint string `json:"endpoint,omitempty"`

	provider *joker.Provider
	logger   *zap.Logger
	expanded bool
}

var (
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
)

// CaddyModule returns module info.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.joker",
		New: func() caddy.Module { return new(Provider) },
	}
}

// Provision validates config and sets up logger.
func (p *Provider) Provision(ctx caddy.Context) error {
	if !p.expanded {
		repl := caddy.NewReplacer()
		p.Username = repl.ReplaceAll(p.Username, "")
		p.Password = repl.ReplaceAll(p.Password, "")
		p.APIToken = repl.ReplaceAll(p.APIToken, "")
		p.Endpoint = repl.ReplaceAll(p.Endpoint, "")
		p.expanded = true
	}

	p.logger = ctx.Logger().Named("dns.joker")
	p.provider = &joker.Provider{
		Username: p.Username,
		Password: p.Password,
		APIToken: p.APIToken,
		Endpoint: p.Endpoint,
	}

	if err := p.provider.Validate(); err != nil {
		return err
	}

	return nil
}

// UnmarshalCaddyfile parses the Caddyfile block:
//
//	dns joker {
//	    username ...
//	    password ...
//	    api_token ...
//	    endpoint ...
//	}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "username":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Username = d.Val()

			case "password":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Password = d.Val()

			case "api_token":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.APIToken = d.Val()

			case "endpoint":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Endpoint = d.Val()

			default:
				return d.Errf("unrecognized directive %q", d.Val())
			}
		}
	}

	return nil
}

// AppendRecords adds DNS records via libdns-joker.
func (p *Provider) AppendRecords(
	ctx context.Context,
	zone string,
	records []libdns.Record,
) ([]libdns.Record, error) {
	if p.provider == nil {
		return nil, fmt.Errorf("provider not provisioned")
	}
	if p.logger != nil {
		p.logger.Debug("adding DNS records",
			zap.String("zone", zone),
			zap.Int("count", len(records)),
		)
	}
	return p.provider.AppendRecords(ctx, zone, records)
}

// DeleteRecords deletes DNS records via libdns-joker.
func (p *Provider) DeleteRecords(
	ctx context.Context,
	zone string,
	records []libdns.Record,
) ([]libdns.Record, error) {
	if p.provider == nil {
		return nil, fmt.Errorf("provider not provisioned")
	}
	if p.logger != nil {
		p.logger.Debug("deleting DNS records",
			zap.String("zone", zone),
			zap.Int("count", len(records)),
		)
	}
	return p.provider.DeleteRecords(ctx, zone, records)
}
