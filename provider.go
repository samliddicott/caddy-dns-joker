package caddydnsjoker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"
)

const defaultEndpoint = "https://svc.joker.com/nic/replace"

func init() {
	caddy.RegisterModule(Provider{})
}

// Provider implements libdns interfaces for Joker DNS
type Provider struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Endpoint string `json:"endpoint,omitempty"`

	client *http.Client
}

var (
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ caddy.Validator      = (*Provider)(nil)
)

// CaddyModule returns module info.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.joker",
		New: func() caddy.Module { return new(Provider) },
	}
}

// Validate ensures the provider is configured correctly.
func (p *Provider) Validate() error {
	if p.Username == "" || p.Password == "" {
		return errors.New("joker: username and password are required")
	}
	return nil
}

func (p *Provider) httpClient() *http.Client {
	if p.client == nil {
		p.client = &http.Client{
			Timeout: 15 * time.Second,
		}
	}
	return p.client
}

func (p *Provider) endpoint() string {
	if p.Endpoint != "" {
		return p.Endpoint
	}
	return defaultEndpoint
}

// AppendRecords adds DNS records via Joker /nic/replace
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var added []libdns.Record

	for _, rec := range records {
		rr := rec.RR()
		value := rr.Data

		// Joker TXT records must not be quoted
		if rr.Type == "TXT" {
			value = strings.Trim(value, `"`)
		}

		if err := p.replaceRecord(ctx, rr.Name, rr.Type, value, int(rr.TTL.Seconds())); err != nil {
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

		// Joker "delete" is implemented as replace with empty address
		if err := p.replaceRecord(ctx, rr.Name, rr.Type, "", int(rr.TTL.Seconds())); err != nil {
			return deleted, err
		}
		deleted = append(deleted, rec)
	}

	return deleted, nil
}

func (p *Provider) replaceRecord(ctx context.Context, name, rtype, value string, ttl int) error {
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
		p.endpoint(),
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("joker API error: %s: %s", resp.Status, string(body))
	}

	return nil
}
