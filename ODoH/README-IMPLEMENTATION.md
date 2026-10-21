# SocksHttpGate ODoH services

This directory contains two separate Go services implementing the ODoH request path:

- **Proxy** — accepts ODoH messages, forwards opaque bytes to a fixed Target origin, and does not hold the Target private key. It does not forward client-supplied IP headers or log individual query names.
- **Target** — publishes ODoH configuration, decrypts requests, checks the configured hosts-format blocklist, resolves allowed names over HTTPS DoH, then encrypts DNS responses.
- **Protocol and integration tests** — cover ODoH config retrieval/decoding, encrypted query/response processing, DNS answer validation, blocklist behavior, malformed input and Proxy forwarding. Some tests use the real public Cloudflare DoH endpoint; they need outbound HTTPS.
- **Legacy reference harness** — `run.sh` downloads an archived reference implementation and is separate from the Go servers.

Protocol reference: [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230.html).

## API specification

The OpenAPI 3.1 specification is maintained in [`openapi.yaml`](./openapi.yaml). It documents the public ODoH protocol endpoints, versioned JSON status/health/stats routes, and aggregate diagnostics. There are deliberately no public endpoints for changing the Target key or blocklist: those operations would need a separate authenticated administrative interface and should not be exposed on the public Proxy.

## GitHub Actions validation

The workflow at [`.github/workflows/odoh.yml`](../.github/workflows/odoh.yml) runs on ODoH changes, pull requests and manual dispatch. It checks module consistency with `go mod tidy -diff`, formats all Go files in Proxy and Target, runs `go vet`, builds both services, runs the race-enabled test suite, performs a bounded 10-second fuzz run, and builds both Docker images.

The end-to-end test requires outbound HTTPS access to `cloudflare-dns.com`. A passing run verifies the exercised path at that commit; it does not certify all ODoH implementations or all DNS names.

## Build and test locally

Requires Go 1.23+ and Docker for image builds.

```sh
cd ODoH
go mod tidy -diff
gofmt -d Proxy/*.go Target/*.go
go vet ./...
go test -race -count=1 -v ./...
go test ./Target -run='^$' -fuzz=FuzzTargetMalformedODoH -fuzztime=10s
go build -trimpath ./Proxy
go build -trimpath ./Target
docker build -f Proxy/Dockerfile -t sockshttpgate-odoh-proxy .
docker build -f Target/Dockerfile -t sockshttpgate-odoh-target .
```

The integration test binds the services to ephemeral loopback ports and uses `ALLOW_INSECURE_TARGET=YES` only for its local HTTP hop. Do not use that override for a public or untrusted network.

## Configuration

Generate a persistent Target key seed:

```sh
openssl rand -hex 32
```

Set the resulting 64-character hex string as the secret `ODOH_KEY_SEED` **on the Target service only**. Never commit it, expose it in logs, or put it in the Proxy environment. Keep it stable across restarts so clients can continue using the same published key configuration.

Target environment:
- `ODOH_KEY_SEED` — required 32-byte seed encoded as 64 hex characters.
- `UPSTREAM_DOH` — HTTPS DoH URL; defaults to Cloudflare.
- `BLOCKLIST` — optional inline domains separated by commas, spaces, or newlines.
- `BLOCKLIST_URLS` — optional comma/semicolon/newline-separated HTTPS hosts-list URLs.
- `BLOCKLIST_REFRESH` — refresh period, default `6h`, minimum `1m`.
- `PORT` or `ADDR` — listen address.

Proxy environment:
- `ODOH_TARGET_URL` — fixed Target origin with no path. HTTPS is required except for an explicitly enabled trusted-private-network HTTP hop.
- `ALLOW_INSECURE_TARGET=YES` — development/private-network exception only; do not enable for a public/untrusted hop.
- `PORT` or `ADDR` — listen address.

Protocol endpoints:
- `GET /.well-known/odohconfigs`
- `POST /proxy` with content type `application/oblivious-dns-message`
- `GET /health`
- `GET /api/stats` and `GET /api/v1/stats` (aggregate counters)
- `GET /api/v1/status` (process status)
- `GET /api/v1/health` (health alias; Proxy checks Target availability)

## Render deployment

The blueprint in `render.yaml` declares a private Target and a public Proxy. Before deploying:

1. Add `ODOH_KEY_SEED` as a secret on the Target only.
2. Set the Proxy's `ODOH_TARGET_URL` to the actual private internal origin assigned to the Target by Render.
3. Prefer HTTPS for the Proxy-to-Target hop where the platform supports it. The blueprint's `ALLOW_INSECURE_TARGET=YES` setting is only acceptable if that hop is guaranteed private and trusted; otherwise remove it and configure HTTPS.
4. Verify deployed health, `/.well-known/odohconfigs`, and a real encrypted query before sending user traffic.

Do not assume an example internal hostname is correct for your deployment; confirm the actual Render internal hostname and port.

## Security and known limitations

**This is not a production security certification or a claim of full RFC 9230 conformance.** The current implementation depends on archived `github.com/cloudflare/odoh-go`. Request handling includes panic recovery for malformed ODoH messages, but this does not repair parser flaws in the dependency. Before exposing the service to real users, replace or independently audit the dependency, validate published RFC 9230 vectors, fuzz malformed ODoH/DNS messages beyond the bounded CI run, review key rotation and replay/abuse handling, and conduct an independent security review.

ODoH reduces direct linkage between the client and DNS Target only when Proxy and Target are operated with meaningful trust separation. If one administrator/provider can observe both services, traffic timing and volume may still be correlated. The Target sees the Proxy's network identity; ODoH does not hide timing or traffic volume. Avoid per-query logging and review infrastructure-level logs too.
