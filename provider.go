package caddydnsjoker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"

	"github.com/libdns/libdns"
)

type rrsetKey struct {
    zone  string
    label string
    rtype string
}

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

// Provision validates config and sets up client + logger.
func (p *Provider) Provision(ctx caddy.Context) error {
	if !p.expanded {
		repl := caddy.NewReplacer()
		p.Username = repl.ReplaceAll(p.Username, "")
		p.Password = repl.ReplaceAll(p.Password, "")
		p.APIToken = repl.ReplaceAll(p.APIToken, "")
		p.Endpoint = repl.ReplaceAll(p.Endpoint, "")
		p.expanded = true
	}
	p.client = &http.Client{
		Timeout: 30 * time.Second,
	}
	p.logger = ctx.Logger().Named("dns.joker")

	if p.Endpoint == "" {
		p.Endpoint = defaultEndpoint
	}

	hasUserPass := p.Username != "" && p.Password != ""
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

// AppendRecords adds DNS records via Joker /nic/replace
func (p *Provider) AppendRecords(
	ctx context.Context,
	zone string,
	records []libdns.Record,
) ([]libdns.Record, error) {

	grouped := make(map[rrsetKey][]libdns.Record)
	z := normalizeZone(zone)

	for _, rec := range records {
		rr := rec.RR()
		key := rrsetKey{
			zone:  z,
			label: labelRelativeToZone(rr.Name, z),
			rtype: rr.Type,
		}
		grouped[key] = append(grouped[key], rec)
	}

	var added []libdns.Record

	for key, recs := range grouped {
		var values []string
		ttl := minTTL(recs)

		for _, rec := range recs {
			v := rec.RR().Data
			if key.rtype == "TXT" {
				v = normalizeTXT(v)
			}
			values = append(values, v)
		}

		p.logger.Debug("adding DNS record",
			zap.String("zone", key.zone),
			zap.String("label", key.label),
			zap.String("type", key.rtype),
		)

		if err := p.replaceRRSet(
			ctx,
			key.zone,
			key.label,
			key.rtype,
			values,
			ttl,
		); err != nil {
			return added, err
		}

		added = append(added, recs...)
	}

	return added, nil
}

// DeleteRecords deletes DNS records via Joker /nic/replace
func (p *Provider) DeleteRecords(
	ctx context.Context,
	zone string,
	records []libdns.Record,
) ([]libdns.Record, error) {

	grouped := make(map[rrsetKey][]libdns.Record)
	z := normalizeZone(zone)

	for _, rec := range records {
		rr := rec.RR()
		key := rrsetKey{
			zone:  z,
			label: labelRelativeToZone(rr.Name, z),
			rtype: rr.Type,
		}
		grouped[key] = append(grouped[key], rec)
	}

	var deleted []libdns.Record

	for key, recs := range grouped {
		ttl := minTTL(recs)

		p.logger.Debug("deleting DNS record",
			zap.String("zone", key.zone),
			zap.String("label", key.label),
			zap.String("type", key.rtype),
		)

		// Empty value list = delete entire RRset
		if err := p.replaceRRSet(
			ctx,
			key.zone,
			key.label,
			key.rtype,
			nil,
			ttl,
		); err != nil {
			return deleted, err
		}

		deleted = append(deleted, recs...)
	}

	return deleted, nil
}

// replaceRRSet calls Joker's /nic/replace endpoint.
// An empty value deletes the record.
func (p *Provider) replaceRRSet(
	ctx context.Context,
	zone, label, rtype string,
	values []string,
	ttl int,
) error {
	zone = normalizeZone(zone)
	label = strings.TrimSuffix(label, ".")

	// Clamp TTL to Joker's documented range (and your requirement)
	if ttl < 60 {
		ttl = 60
	} else if ttl > 86400 {
		ttl = 86400
	}

	form := url.Values{}
	if p.APIToken != "" {
		form.Set("api_token", p.APIToken)
	} else {
		form.Set("username", p.Username)
		form.Set("password", p.Password)
	}

	form.Set("zone", zone)
	form.Set("label", label)
	form.Set("type", rtype)
	form.Set("ttl", strconv.Itoa(ttl))

	if len(values) > 0 {
		form.Set("value", strings.Join(values, ","))
	} else {
		form.Set("value", "")
	}

	// Safe debug logging (no secrets)
	p.logFormRedacted(form)

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

// Select the minimum TTL of all records, as with joker single update they
// must share one TTL, but ensure it is within the joker permitted range
func minTTL(records []libdns.Record) int {
	if len(records) == 0 {
		return 60
	}

	min := int(records[0].RR().TTL.Seconds())
	for _, r := range records[1:] {
		if t := int(r.RR().TTL.Seconds()); t < min {
			min = t
		}
	}

	if min < 60 {
		min = 60
	} else if min > 86400 {
		min = 86400
	}
	return min
}

func normalizeZone(z string) string {
    return strings.TrimSuffix(z, ".")
}

func labelRelativeToZone(name, zone string) string {
	name = strings.TrimSuffix(name, ".")
	zone = strings.TrimSuffix(zone, ".")

	// If already relative (no zone suffix), keep it as-is.
	// If it ends with ".<zone>", strip that suffix.
	suffix := "." + zone
	if strings.HasSuffix(name, suffix) {
		name = strings.TrimSuffix(name, suffix)
	}
	return strings.TrimSuffix(name, ".")
}

func (p *Provider) logFormRedacted(form url.Values) {
	redacted := url.Values{}
	for k, v := range form {
		switch k {
		case "password", "api_token":
			redacted.Set(k, "<redacted>")
		default:
			redacted[k] = v
		}
	}
	p.logger.Debug("joker request form", zap.Any("form", redacted))
}

