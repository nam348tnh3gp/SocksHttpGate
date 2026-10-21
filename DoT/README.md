# DNS-over-TLS (DoT)

[![DoT CI](https://img.shields.io/github/actions/workflow/status/nam348tnh3gp/SocksHttpGate/test-dot.yml?branch=main&style=for-the-badge&label=DoT%20CI)](https://github.com/nam348tnh3gp/SocksHttpGate/actions/workflows/test-dot.yml)
[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![Protocol](https://img.shields.io/badge/Protocol-DNS--over--TLS-2496ED?style=for-the-badge&logo=letsencrypt&logoColor=white)](#dns-over-tls-dot)
[![Port](https://img.shields.io/badge/Default%20Port-TCP%20853-555555?style=for-the-badge)](#run-on-a-linux-vps)
[![TLS](https://img.shields.io/badge/TLS-1.2%2B-success?style=for-the-badge&logo=letsencrypt&logoColor=white)](#configuration)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?style=for-the-badge&logo=docker&logoColor=white)](#docker)
[![Blocklists](https://img.shields.io/badge/Blocklists-Supported-2E8B57?style=for-the-badge)](#configuration)
[![Dashboard](https://img.shields.io/badge/Web%20Dashboard-Included-6f42c1?style=for-the-badge)](#web-dashboard)
[![Last commit](https://img.shields.io/github/last-commit/nam348tnh3gp/SocksHttpGate/main/DoT?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate/commits/main/DoT)
[![License](https://img.shields.io/github/license/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](../LICENSE)

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
| `BLOCKLIST_URLS` | empty | Comma/semicolon/space-separated HTTPS blocklist URLs (hosts and adblock formats) |
| `BLOCKLIST_REFRESH` | `6h` | Remote blocklist refresh interval; minimum `1m` |
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

The dashboard starts alongside the DNS listener at `http://127.0.0.1:8080` by default. It displays live query counters, uptime, upstream/listener details, recent DNS logs, and lets you add/remove blocklist domains at runtime. The dashboard also exposes remote blocklist source health and supports runtime upstream changes. Remote lists refresh using `BLOCKLIST_URLS` and `BLOCKLIST_REFRESH`; manually added/removed domains are runtime-only and reset on restart or the next remote refresh. JSON endpoints include `/api/stats`, `/api/logs`, `/api/blocklist`, and `/api/upstream`. POST to `/api/upstream` with `{"upstream":"1.1.1.1:853","tls_name":"cloudflare-dns.com"}`.

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

## Test and CI

Run from this directory with Go 1.23 or newer:

```sh
go mod tidy -diff
test -z "$(gofmt -l *.go)"
go test -count=1 ./...
go vet ./...
go build -trimpath -o dot .
docker build -t sockshttpgate-dot:ci .
```

The [DoT workflow](../.github/workflows/test-dot.yml) runs on pushes, pull requests and manual dispatch. In addition to these checks, it starts the service with a temporary self-signed certificate, checks the dashboard readiness endpoint, and sends a DoT DNS query. That query uses the configured upstream resolver, so outbound DNS-over-TLS connectivity is required for the end-to-end smoke test.
