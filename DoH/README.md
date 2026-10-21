# Go DNS-over-HTTPS (DoH)

[![DoH CI](https://img.shields.io/github/actions/workflow/status/nam348tnh3gp/SocksHttpGate/test-doh.yml?branch=main&style=for-the-badge&label=DoH%20CI)](https://github.com/nam348tnh3gp/SocksHttpGate/actions/workflows/test-doh.yml)
[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![Protocol](https://img.shields.io/badge/Protocol-RFC%208484-2496ED?style=for-the-badge)](https://www.rfc-editor.org/rfc/rfc8484)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?style=for-the-badge&logo=docker&logoColor=white)](Dockerfile)
[![Blocklists](https://img.shields.io/badge/Blocklists-Supported-2E8B57?style=for-the-badge)](#blocklists)

Standalone Go DNS-over-HTTPS forwarder with a web dashboard and configurable blocklists. It is independent of the SOCKS5/HTTP proxy implementations and does not automatically become their DNS backend.

## Endpoints

- `POST /dns-query` — accepts a DNS wire-format message with `Content-Type: application/dns-message`.
- `GET /health` — health check for deployment platforms.
- `/` — web dashboard.
- Additional dashboard/API routes are implementation-specific; inspect the source before exposing management endpoints.

## Requirements

- Go 1.23 or newer.
- Network access to the configured upstream HTTPS DoH resolver.
- Docker for container deployment (optional).

## Run locally

```sh
cd DoH
go mod download
go test ./...
go vet ./...
go build -trimpath -ldflags="-s -w" -o doh .
PORT=8080 ./doh
```

Open `http://127.0.0.1:8080/` for the dashboard and `http://127.0.0.1:8080/health` for the health endpoint. For actual DNS requests, send DNS wire-format bytes to `/dns-query`; a browser GET is not a DNS query.

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `8080` locally; supplied by Render | HTTP listen port |
| `UPSTREAM_DOH` | `https://cloudflare-dns.com/dns-query` | Upstream DoH URL |
| `BLOCKLIST` | Built-in defaults | Additional blocked domains separated by commas, semicolons, spaces or newlines |
| `BLOCKLIST_URLS` | Empty unless configured | HTTPS URLs for domain lists, hosts files and common adblock-style entries |
| `BLOCKLIST_REFRESH` | `6h` | Go duration for remote list refresh; minimum `1m` |

Example:

```sh
export UPSTREAM_DOH=https://cloudflare-dns.com/dns-query
export BLOCKLIST_URLS=https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
export BLOCKLIST_REFRESH=6h
export BLOCKLIST=custom-ad.example,tracker.example
go run .
```

Remote lists are loaded at startup and refreshed periodically. Downloads are bounded (10 MiB per source) and use a timeout. If all remote sources fail, the service keeps its current list instead of replacing it with an empty list. A blocked domain or its subdomain receives an NXDOMAIN response. Large public lists may cause false positives; validate your chosen sources.

## Docker

Build from this directory:

```sh
docker build -t sockshttpgate-doh .
docker run --rm -p 8080:8080 \
  -e UPSTREAM_DOH=https://cloudflare-dns.com/dns-query \
  -e BLOCKLIST_REFRESH=6h \
  sockshttpgate-doh
``

The image runs as a non-root user and listens on port 8080 by default.

## Deploy on Render

The included `render.yaml` defines a Docker Web Service and `/health` health check. You can deploy using the repository blueprint or create a Web Service with `DoH` as the root directory and the Dockerfile in that directory. The public endpoint will be:

`https://YOUR-SERVICE.onrender.com/dns-query`

Render's managed web ingress is HTTPS/HTTP; it does not expose arbitrary public UDP/TCP port 53 or TCP 853. This service is DoH, not DoT.

## Android clients

Use a DNS app that accepts a custom DoH URL and enter `https://YOUR-SERVICE.onrender.com/dns-query`. Android's built-in **Private DNS** setting expects a DoT provider hostname, not a DoH URL.

## Testing

```sh
cd DoH
go mod tidy -diff
test -z "$(gofmt -l *.go)"
go test -count=1 ./...
go vet ./...
go build ./...
docker build -t sockshttpgate-doh:ci .
``

The CI smoke test starts the service locally and checks health/dashboard plus a real DoH query. The real query depends on outbound access to the configured upstream resolver.

## Security and limitations

- This is a starter resolver, not a drop-in replacement for large curated blocklist products.
- Unless access controls are added at the hosting layer, a public URL can be used by anyone who knows it. Consider rate limiting and abuse controls before public production use.
- The configured upstream receives DNS queries. Use providers you trust.
- DoH is not integrated into each proxy implementation by default.
- Keep secrets and private configuration out of version control.
