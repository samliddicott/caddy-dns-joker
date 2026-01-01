# caddy-dns-joker

A **Caddy DNS provider plugin** for the [Joker.com](https://joker.com) DNS API, enabling **DNS-01 ACME challenges** (e.g. Let’s Encrypt) via Joker-managed domains.

This plugin implements the [`libdns`](https://github.com/libdns/libdns) interfaces and integrates cleanly with Caddy v2 and CertMagic.

---

## Features

- ✅ DNS-01 support for Joker.com
- ✅ Compatible with Caddy v2 ACME / CertMagic
- ✅ Supports **API token authentication** (recommended)
- ✅ Supports **username/password authentication** (legacy)
- ✅ Configurable API endpoint (useful for testing/proxies)
- ✅ TXT record normalization
- ✅ Context-aware HTTP requests (clean shutdowns, cancellations)
- ✅ Structured logging via Caddy / Zap

---

## Requirements

- **Caddy v2.10.2+**
- **Go 1.25+** (as required by Caddy)
- A Joker.com account with DNS management enabled

---

## Installation

This plugin is **not bundled with Caddy by default**.  
You must build Caddy with the plugin included.

### Using `xcaddy` (recommended)

```bash
xcaddy build \
  --with github.com/samliddicott/caddy-dns-joker
```

---

## Configuration

### Caddyfile (API token – recommended)

```caddyfile
{
    email you@example.com
}

example.com {
    tls {
        dns joker {
            api_token "{env.JOKER_API_TOKEN}"
        }
    }

    respond "Hello from Caddy + Joker DNS!"
}
```

### Caddyfile (username/password – legacy)

```caddyfile
tls {
    dns joker {
        username "{env.JOKER_USERNAME}"
        password "{env.JOKER_PASSWORD}"
    }
}
```

### Optional: Custom API endpoint

```caddyfile
tls {
    dns joker {
        api_token "{env.JOKER_API_TOKEN}"
        endpoint "https://svc.joker.com/nic/replace"
    }
}
```

If omitted, the endpoint defaults to:

```
https://svc.joker.com/nic/replace
```

---

## Environment Variables

It is **strongly recommended** to provide credentials via environment variables:

```bash
export JOKER_API_TOKEN=your_token_here
```

or (legacy):

```bash
export JOKER_USERNAME=your_username
export JOKER_PASSWORD=your_password
```

---

## Docker / Multi-Arch Builds

This plugin is compatible with Caddy builds created using:

- `xcaddy`
- Docker + `caddy:builder`
- `docker buildx` (amd64 / arm64)

A common pattern is to **build and push a multi-arch image**:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t yourrepo/caddy-joker:latest \
  --push \
  .
```

Then pull and run on your target system (e.g. QNAP, ARM SBCs, VPS).

---

## Logging

The plugin uses Caddy’s structured logging system.

Example log namespace:

```
dns.joker
```

Errors returned by the Joker API include:

- HTTP status
- Response body (when available)

Sensitive credentials are **never logged**.

---

## Development Notes

- The plugin follows patterns used by official `caddy-dns-*` providers
- HTTP requests are context-aware for clean cancellation
- TXT record values are normalized to avoid quoting issues during ACME challenges

---

## Acknowledgements

This plugin was developed by **Sam Liddicott**,  
with design review, iteration, and implementation assistance from **ChatGPT instance Fred**.

ChatGPT instance Fred assisted with:

- Code structure and API design
- Caddy/libdns integration patterns
- Error handling and logging practices
- Docker and build workflows

Final design decisions, testing, and validation were performed by the author.

---

## License

MIT License

---

## Disclaimer

This project is **not affiliated with or endorsed by Joker.com**.  
Use at your own risk.
