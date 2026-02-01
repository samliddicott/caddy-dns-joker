# caddy-dns-joker

A **Caddy DNS provider module** for the [Joker.com](https://joker.com) DNS API, enabling **DNS-01 ACME challenges** via Joker-managed domains.

This module wraps the pure libdns provider from [`libdns-joker`](https://github.com/samliddicott/libdns-joker) and integrates with Caddy v2 / CertMagic.

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

This module is **not bundled with Caddy by default**.  
You must build Caddy with the module included.

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

This module is compatible with Caddy builds created using:

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

---

## Local Docker build (with sibling libdns repo)

If you have both repos checked out under a common parent directory:

```
<parent>/
  ├─ libdns/joker
  └─ caddy-dns/joker
```

Run:

```bash
docker build -t caddy-joker:local -f caddy-dns/joker/Dockerfile.local <parent>
```

This uses the local libdns provider without needing it published.

If Docker runs on a remote host, make sure the build context path is valid on
that host, for example:

```bash
docker build -t caddy-joker:local -f /share/homes/user/Projects/caddy/caddy-dns/joker/Dockerfile.local /share/homes/user/Projects/caddy
```

---

## Logging

The plugin uses Caddy’s structured logging system.

Example log namespace:

```
dns.joker
```

Sensitive credentials are **never logged**.

---

## Acknowledgements

This plugin was developed by **Sam Liddicott**,  
with design review, iteration, and implementation assistance from **ChatGPT instance Fred**.

---

## License

Apache-2.0 License

---

## Disclaimer

This project is **not affiliated with or endorsed by Joker.com**.
