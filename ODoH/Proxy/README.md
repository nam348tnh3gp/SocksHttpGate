# ODoH Proxy service

This is the Go ODoH Proxy component. It accepts ODoH HTTP messages and forwards opaque encrypted payloads to a fixed Target origin. It must not contain the Target's private key seed.

## Requirements and run

Requires Go 1.23+ and the parent module's dependencies.

```sh
cd ODoH
go build -trimpath -o /tmp/odoh-proxy ./Proxy
ODOH_TARGET_URL=https://YOUR-TARGET-ORIGIN /tmp/odoh-proxy
```

The default listen address is `:8080`; override it with `PORT` or `ADDR`.

## Configuration

- `ODOH_TARGET_URL` — required fixed Target origin. It must not include a path, query, fragment or user info. HTTPS is required by default.
- `ALLOW_INSECURE_TARGET=YES` — allows HTTP only for a trusted private-network development hop; never enable it for a public/untrusted network.
- `PORT` — listen port if `ADDR` is not set.
- `ADDR` — explicit listen address, which takes precedence over `PORT`.
- `TLS_CERT` and `TLS_KEY` — optional pair for the Proxy's own TLS listener when running outside a TLS-terminating platform.

## Endpoints

- `GET /.well-known/odohconfigs` — forwards Target configuration.
- `POST /proxy` — forwards requests with content type `application/oblivious-dns-message`.
- `GET /health`, `GET /api/stats`, `GET /api/v1/stats`, `GET /api/v1/status`.

## Test and build

Run from `ODoH/`:

```sh
go test -race -count=1 ./Proxy
go vet ./...
go build ./Proxy
docker build -f Proxy/Dockerfile -t sockshttpgate-odoh-proxy .
```

The parent [ODoH README](../README.md) documents the paired Proxy/Target integration tests and Render blueprint.

## Security

Keep the Target private key seed exclusively on Target. Use HTTPS for Proxy-to-Target communication unless the hop is guaranteed private and trusted. Do not expose administrative or diagnostic endpoints beyond what is needed.
