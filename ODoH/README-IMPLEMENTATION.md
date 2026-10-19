# SocksHttpGate ODoH services

This directory contains two separate Go services implementing the ODoH request path:

- **Proxy** — accepts ODoH messages, forwards opaque bytes to a fixed Target origin, and does not hold the Target private key. It does not forward client-supplied IP headers or log individual queries/domains.
- **Target** — publishes ODoH configuration, decrypts requests, checks the configured hosts-format blocklist, resolves allowed names over HTTPS DoH, then encrypts the DNS response.
- **Integration test** — starts both actual service binaries locally and sends encrypted requests through the Proxy to the Target. Allowed-domain resolution uses the real public Cloudflare DoH endpoint; the blocked-domain case verifies NXDOMAIN.

Protocol reference: [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230.html).

## API specification

The OpenAPI 3.1 specification is maintained in [`openapi.yaml`](./openapi.yaml). It documents the public ODoH protocol endpoints and aggregate diagnostics. There are deliberately no public endpoints for changing the Target key or blocklist: those operations would need a separate authenticated administrative interface and should not be exposed on the public Proxy.

## GitHub Actions validation

The workflow at `.github/workflows/odoh.yml` runs on ODoH changes and manually. It performs:

1. Dependency resolution with `go mod tidy`.
2. A `gofmt` gate for the maintained Proxy security regression tests, followed by `go vet ./...`.
3. Builds both Go services.
4. Runs `go test -race -count=1 -v ./...`, including the real Proxy → Target → Cloudflare DoH integration test.
5. Runs a bounded 10-second Go fuzzing session against malformed ODoH Target messages. This is a smoke fuzz run, not exhaustive fuzz coverage.
6. Builds both Docker images.

The end-to-end tests require outbound HTTPS access to `cloudflare-dns.com`. A passing run verifies the tested path at that commit; it does not certify all ODoH implementations or all DNS names.

## Build and test locally

Requires Go 1.23+ and Docker for image builds.

```sh
cd ODoH
go mod tidy
go vet ./...
go test -race -count=1 -v ./...
go build -trimpath ./Proxy
go build -trimpath ./Target
docker build -f Proxy/Dockerfile -t sockshttpgate-odoh-proxy .
docker build -f Target/Dockerfile -t sockshttpgate-odoh-target .
```

The integration test binds both services to ephemeral loopback ports and uses `ALLOW_INSECURE_TARGET=YES` only for its local HTTP hop. Do not use that override for a public or untrusted network.

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

Endpoints on both services:
- `GET /.well-known/odohconfigs`
- `POST /proxy` (ODoH content type: `application/oblivious-dns-message`)
- `GET /health`
- `GET /api/stats` (aggregate counters only)

## Render deployment

The blueprint in `render.yaml` declares a private Target and a public Proxy. Before deploying:

1. Add `ODOH_KEY_SEED` as a secret on the Target only.
2. Set the Proxy's `ODOH_TARGET_URL` to the actual private internal origin assigned to the Target by Render.
3. Prefer HTTPS for the Proxy-to-Target hop where the platform supports it. The blueprint's `ALLOW_INSECURE_TARGET=YES` setting is only acceptable if that hop is guaranteed private and trusted; otherwise remove it and configure HTTPS.
4. Verify the deployed `/health`, `/.well-known/odohconfigs`, and a real encrypted query before sending user traffic.

Do not assume the example internal hostname in documentation is correct for your deployed service; confirm the actual Render internal hostname and port.

## Security and known limitations

**This is not yet a production security certification or a claim of full RFC 9230 conformance.** The current implementation depends on archived `github.com/cloudflare/odoh-go`. Request handling includes panic recovery for malformed ODoH messages; this reduces the risk of a malformed request crashing the Target process, but it does not repair parser flaws in the dependency. The test suite covers the end-to-end path and bounded fuzz smoke run, but an archived protocol library remains a material maintenance and security risk. Before exposing this to real users, replace or independently audit the dependency, validate published RFC 9230 test vectors, fuzz malformed ODoH/DNS messages, review key rotation and replay/abuse handling, and conduct an independent security review.

ODoH reduces direct linkage between the client and the DNS Target only when the Proxy and Target are operated with meaningful trust separation. If one administrator/provider can observe both services, traffic timing and volume may still be correlated. The Target sees the Proxy's network identity; ODoH does not hide timing or traffic volume. No individual-query logging is intended, but infrastructure/provider-level logging must also be reviewed.

Blocklist refresh keeps the last-known-good list when refresh sources fail and an existing list is present. Configure trustworthy HTTPS sources and monitor aggregate stats. The Proxy's `/health` endpoint checks that the Target's `/health` endpoint responds successfully, so Render can detect an unavailable Target; this is a readiness check, not a full encrypted DNS transaction test.

**Do not enter this ODoH Proxy URL into a DoH-only field in Rethink DNS.** ODoH uses `application/oblivious-dns-message` at `/proxy`; conventional DoH uses `application/dns-message` at `/dns-query`. This service does not implement a conventional DoH endpoint, and the two protocols are not interchangeable.
