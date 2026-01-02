FROM caddy:builder AS builder

ARG BUILD_PLUGIN=github.com/samliddicott/caddy-dns-joker@latest

RUN set -eux; \
    xcaddy build v2.10.2 \
      --with "$BUILD_PLUGIN" \
      --output /usr/bin/caddy

FROM caddy:2.10.2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

EXPOSE 80 443

ENV JOKER_USERNAME=""
ENV JOKER_PASSWORD=""

RUN mkdir -p /etc/caddy && \
    printf "localhost {\n  respond \"Hello from Caddy + Joker DNS\"\n}\n" \
    > /etc/caddy/Caddyfile

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
