# ODoH Target service

This is the Go ODoH Target component. It publishes ODoH configuration, decrypts encrypted requests, applies the configured blocklist, resolves permitted DNS queries through an upstream DoH resolver, and encrypts responses.

## Requirements and run

Requires Go 1.23+ and the parent module's dependencies. Generate a stable 32-byte seed encoded as 64 hexadecimal characters:

```sh
openssl rand -hex 32
```

Set that value as a secret, then build/run from `ODoH/`:

```sh
go build -trimpath -o /tmp/odoh-target ./Target
ODOH_KEY_SEED=YOUR_64_HEX_CHARACTER_SEED /tmp/odoh-target
```

The default listen address is `:8080`; override it with `PORT` or `ADDR`.

## Configuration

- `ODOH_KEY_SEED` — required 32-byte seed encoded as 64 hex characters. Keep it stable across restarts and never commit it.
- `UPSTREAM_DOH` — upstream HTTPS DoH URL; defaults to Cloudflare.
- `BLOCKLIST` — inline blocked domains separated by commas, semicolons, spaces or newlines.
- `BLOCKLIST_URLS` — optional HTTPS list URLs.
- `BLOCKLIST_REFRESH` — remote list refresh interval; default `6h`, minimum `1m`.
- `PORT` / `ADDR` — listener configuration.

## Endpoints

- `GET /.well-known/odohconfigs` — publishes Target public configuration.
- `POST /proxy` — accepts encrypted ODoH requests.
- `GET /health`, `GET /api/stats`, `GET /api/v1/stats`, `GET /api/v1/status`.

## Test and build

Run from `ODoH/`:

```sh
go test -race -count=1 ./Target
go test ./Target -run='^$' -fuzz=FuzzTargetMalformedODoH -fuzztime=10s
go vet ./...
go build ./Target
docker build -f Target/Dockerfile -t sockshttpgate-odoh-target .
```

Some integration tests use the real Cloudflare DoH endpoint and require outbound HTTPS. See the parent [ODoH README](../README.md) for the complete service setup.

## Security

Keep this service private and reachable only by the intended Proxy where possible. The Target is the only component that should receive `ODOH_KEY_SEED`. The current implementation uses an archived ODoH dependency; passing tests do not replace RFC-vector validation or an independent security review.
