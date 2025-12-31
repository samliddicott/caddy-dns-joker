package caddydnsjoker

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/libdns/libdns"
	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Provider{})
}

// Provider implements libdns interfaces for Joker DNS
type Provider struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var _ libdns.RecordAppender = (*Provider)(nil)
var _ libdns.RecordDeleter = (*Provider)(nil)

// CaddyModule returns module info.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.joker",
		New: func() caddy.Module { return new(Provider) },
	}
}

// AppendRecords adds DNS records via Joker /nic/replace
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var added []libdns.Record
	for _, rec := range records {
		rr := rec.RR()
		if err := p.replaceRecord(zone, rr.Name, rr.Type, rr.Data, int(rr.TTL.Seconds())); err != nil {
			return added, err
		}
		added = append(added, rec)
	}
	return added, nil
}

// DeleteRecords deletes DNS records via Joker /nic/replace
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deleted []libdns.Record
	for _, rec := range records {
		rr := rec.RR()
		if err := p.replaceRecord(zone, rr.Name, rr.Type, "", int(rr.TTL.Seconds())); err != nil {
			return deleted, err
		}
		deleted = append(deleted, rec)
	}
	return deleted, nil
}

// replaceRecord calls Joker's /nic/replace endpoint using HTTP POST
func (p *Provider) replaceRecord(zone, name, rtype, value string, ttl int) error {
	form := url.Values{}
	form.Set("username", p.Username)
	form.Set("password", p.Password)
	form.Set("hostname", name)
	form.Set("type", rtype)
	form.Set("address", value)
	form.Set("ttl", fmt.Sprintf("%d", ttl))

	resp, err := http.PostForm("https://svc.joker.com/nic/replace", form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("joker API error: %s", resp.Status)
	}
	return nil
}
