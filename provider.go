package caddydnsjoker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyfile"
	"go.uber.org/zap"

	"github.com/libdns/libdns"
)

func init() {
	caddy.RegisterModule(Provider{})
}

// Provider implements libdns interfaces for Joker DNS
type Provider struct {
	Username string `json:"username"`
	Password string `json:"password"`

	client *http.Client
	logger *zap.Logger
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

// Provision sets up the HTTP client and logger.
func (p *Provider) Provision(ctx caddy.Context) error {
	p.client = &http.Client{
		Timeout: 30 * time.Second,
	}
	p.logger = ctx.Logger().Named("dns.joker")
	return nil
}

// UnmarshalCaddyfile parses the Caddyfile block:
//
// dns joker {
//     username ...
//     password ...
// }
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock() {
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

			default:
				return d.Errf("unrecognized directive %q", d.Val())
			}
		}
	}

	if p.Username == "" || p.Password == "" {
		return d.Err("both username and password are required")
	}

	return nil
}

// AppendRecords adds DNS records via Joker /nic/replace
func (p *Provider) AppendRecords(
	ctx context.Context,
	zone string,
	records []libdns.Record,
) ([]libdns.Record, error) {

	var added []libdns.Record

	for _, rec := range records {
		rr := rec.RR()

		p.logger.Debug("adding DNS record",
			zap.String("zone", zone),
			zap.String("name", rr.Name),
			zap.String("type", rr.Type),
		)

		if err := p.replaceRecord(
			ctx,
			rr.Name,
			rr.Type,
			rr.Data,
			int(rr.TTL.Seconds()),
		); err != nil {
			return added, err
		}

		added = append(added, rec)
	}

	return added, nil
}

// DeleteRecords deletes DNS records via Joker /nic/replace
func (p *Provider) DeleteRecords(
	ctx context.Context,
	zone string,
	records []libdns.Record,
) ([]libdns.Record, error) {

	var deleted []libdns.Record

	for _, rec := range records {
		rr := rec.RR()

		p.logger.Debug("deleting DNS record",
			zap.String("zone", zone),
			zap.String("name", rr.Name),
			zap.String("type", rr.Type),
		)

		if err := p.replaceRecord(
			ctx,
			rr.Name,
			rr.Type,
			"",
			int(rr.TTL.Seconds()),
		); err != nil {
			return deleted, err
		}

		deleted = append(deleted, rec)
	}

	return deleted, nil
}

// replaceRecord calls Joker's /nic/replace endpoint.
// An empty value deletes the record.
func (p *Provider) replaceRecord(
	ctx context.Context,
	name, rtype, value string,
	ttl int,
) error {

	form := url.Values{}
	form.Set("username", p.Username)
	form.Set("password", p.Password)
	form.Set("hostname", name)
	form.Set("type", rtype)
	form.Set("address", value)
	form.Set("ttl", fmt.Sprintf("%d", ttl))

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://svc.joker.com/nic/replace",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)

		p.logger.Error("joker API error",
			zap.Int("status", resp.StatusCode),
			zap.ByteString("response", body),
		)

		return fmt.Errorf(
			"joker API error: status=%d response=%s",
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	return nil
}
