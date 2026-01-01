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

const defaultEndpoint = "https://svc.joker.com/nic/replace"

func init() {
	caddy.RegisterModule(Provider{})
}

// Provider implements libdns interfaces for Joker DNS
type Provider struct {
	// Authentication (exactly one method required)
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	APIToken string `json:"api_token,omitempty"`

	// Optional override
	Endpoint string `json:"endpoint,omitempty"`

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

// Provision validates config and sets up client + logger.
func (p *Provider) Provision(ctx caddy.Context) error {
	p.client = &http.Client{
		Timeout: 30 * time.Second,
	}
	p.logger = ctx.Logger().Named("dns.joker")

	if p.Endpoint == "" {
		p.Endpoint = defaultEndpoint
	}

	hasUserPass := p.Username != "" || p.Password != ""
	hasToken := p.APIToken != ""

	switch {
	case hasToken && hasUserPass:
		return fmt.Errorf("configure either api_token or username/password, not both")
	case hasToken:
		// ok
	case p.Username != "" && p.Password != "":
		// ok
	default:
		return fmt.Errorf("either api_token or username/password must be configured")
	}

	return nil
}

// UnmarshalCaddyfile parses the Caddyfile block:
//
// dns joker {
//     username ...
//     password ...
//     api_token ...
//     endpoint ...
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

// AppendRecords adds DNS records via Joker /nic/replace
func (p *Provider) AppendRecords(
	ctx context.Context,
	zone string,
	records []libdns.Record,
) ([]libdns.Record, error) {

	var added []libdns.Record

	for _, rec := range records {
		rr := rec.RR()

		value := rr.Data
		if rr.Type == "TXT" {
			value = normalizeTXT(value)
		}

		p.logger.Debug("adding DNS record",
			zap.String("zone", zone),
			zap.String("name", rr.Name),
			zap.String("type", rr.Type),
		)

		if err := p.replaceRecord(
			ctx,
			rr.Name,
			rr.Type,
			value,
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
	form.Set("hostname", name)
	form.Set("type", rtype)
	form.Set("address", value)
	form.Set("ttl", fmt.Sprintf("%d", ttl))

	if p.APIToken != "" {
		form.Set("api_token", p.APIToken)
	} else {
		form.Set("username", p.Username)
		form.Set("password", p.Password)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		p.Endpoint,
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

// normalizeTXT removes surrounding quotes from TXT values if present.
func normalizeTXT(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return strings.Trim(v, `"`)
	}
	return v
}
