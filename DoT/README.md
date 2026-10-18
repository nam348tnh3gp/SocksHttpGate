# DNS-over-TLS (DoT)

Standalone DNS-over-TLS forwarder for Android Private DNS. This service is separate from `../DoH`; it does not change the existing DoH service.

## Features

- DNS-over-TLS over TCP port 853, with TLS 1.2 or newer.
- Validates the upstream server certificate and hostname.
- Forwards DNS requests to an upstream DoT resolver (Cloudflare by default).
- Blocks configured domains and their subdomains with NXDOMAIN responses.
- Logs query domain, type, response code, and client address. Consider privacy before enabling public access.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `DOT_ADDR` | `:853` | TCP listen address |
| `TLS_CERT_FILE` | `cert.pem` | Path to the server certificate PEM |
| `TLS_KEY_FILE` | `key.pem` | Path to the private key PEM |
| `UPSTREAM_DOT` | `1.1.1.1:853` | Upstream DoT host and port |
| `UPSTREAM_TLS_NAME` | `cloudflare-dns.com` | TLS hostname used to verify the upstream |
| `BLOCKLIST` | built-in entries | Extra domains separated by commas, spaces, semicolons, or newlines |
| `DASHBOARD_ADDR` | `127.0.0.1:8080` | Local web dashboard listen address |

The upstream TLS hostname must match the provider configured in `UPSTREAM_DOT`. For another provider, change both values accordingly. Do not disable TLS verification.

## Run on a Linux VPS

You need a domain name pointing to the VPS, a firewall/security-group rule allowing inbound **TCP 853**, and a valid certificate for that domain. For example, with a certificate issued by Let's Encrypt:

```sh
cd DoT
export TLS_CERT_FILE=/etc/letsencrypt/live/dot.example.com/fullchain.pem
export TLS_KEY_FILE=/etc/letsencrypt/live/dot.example.com/privkey.pem
export DOT_ADDR=:853
export UPSTREAM_DOT=1.1.1.1:853
export UPSTREAM_TLS_NAME=cloudflare-dns.com
export BLOCKLIST='ads.example,tracker.example'
go run .
```

Install Go 1.23 or newer and run `go mod download` first if needed. The certificate and private key must be readable by the service account. Never commit private keys or production certificates to Git.

## Web dashboard

The dashboard starts alongside the DNS listener at `http://127.0.0.1:8080` by default. It displays live query counters, uptime, upstream/listener details, recent DNS logs, and lets you add/remove blocklist domains at runtime. The blocklist changes are in-memory only and reset when the process restarts. JSON endpoints are `/api/stats`, `/api/logs`, and `/api/blocklist` (GET; POST to `/api/blocklist` with `{"action":"add","domain":"ads.example"}` or `{"action":"remove","domain":"ads.example"}`).

**Security:** the dashboard API has no authentication, so keep `DASHBOARD_ADDR` on `127.0.0.1` unless you place it behind a trusted authenticated reverse proxy. Do not expose it to the public internet.

## Docker

Build the image from this directory:

```sh
docker build -t sockshttpgate-dot .
docker run --rm --name dot-server \
  -p 853:853/tcp \
  -v /etc/letsencrypt/live/dot.example.com:/certs:ro \
  -e TLS_CERT_FILE=/certs/fullchain.pem \
  -e TLS_KEY_FILE=/certs/privkey.pem \
  -e BLOCKLIST='ads.example,tracker.example' \
  sockshttpgate-dot
```

If your environment does not permit a non-root process to bind port 853, grant only the required bind capability or use a host-level port-forwarding rule; do not run the process as root unnecessarily.

## Android Private DNS

On Android, open **Settings → Network & Internet → Private DNS** (menu names vary), select the provider hostname, and enter the certificate-covered hostname, for example `dot.example.com`. Enter the hostname only, not `https://` and not a URL path.

## Important deployment note

Render Web Services generally expose HTTP/HTTPS through their managed ingress and do not provide arbitrary inbound TCP port 853. Deploy this service on a VPS or another platform that explicitly supports raw TCP ingress on port 853. The existing DoH service on Render can continue running independently.

## Test

```sh
go test ./...
go build ./...
```
