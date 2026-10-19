# SocksHttpGate ODoH services — initial implementation

Two separate Go services:
- **Proxy**: opaque forwarding only. It does not import the ODoH crypto library, possess the Target key, forward client IP headers, or log individual queries/domains.
- **Target**: owns the HPKE key, decrypts ODoH messages, resolves DNS over HTTPS, applies a hosts-format blocklist, and encrypts responses. Logs only aggregate blocklist refresh counts.

Protocol reference: [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230.html). This first version uses archived Cloudflare `odoh-go`; it requires independent review and RFC test-vector verification before real traffic.

## Local build

Requires Go 1.23+.

```sh
cd ODoH
go mod tidy
go test ./...
go build ./Proxy ./Target
```

Generate a persistent Target-only key seed with `openssl rand -hex 32`. Store the result as secret `ODOH_KEY_SEED` on **Target only**. Never put it in the Proxy environment or repository. Keep the same seed across restarts.

Target environment: `ODOH_KEY_SEED` (required, 64 hex chars), `UPSTREAM_DOH` (HTTPS URL), optional `BLOCKLIST`, optional `BLOCKLIST_URLS` (HTTPS hosts-file URLs), `BLOCKLIST_REFRESH` (minimum 1m; default 6h), `PORT` or `ADDR`.

Proxy environment: `ODOH_TARGET_URL` (fixed Target origin, no path; HTTPS required except explicit private-test override `ALLOW_INSECURE_TARGET=YES`), `PORT` or `ADDR`.

Endpoints: `GET /.well-known/odohconfigs`, `POST /proxy`, `GET /health`, `GET /api/stats` (aggregate counters only).

## Deployment / limitations

The Render blueprint keeps Target private and Proxy public. Set the Proxy's `ODOH_TARGET_URL` manually to the Target's internal origin, e.g. `http://sockshttpgate-odoh-target:8080` only if that is the actual private hostname/port Render assigns. The blueprint allows HTTP only for this private hop; use HTTPS if supported. Add `ODOH_KEY_SEED` manually as a Target secret.

For meaningful separation, Proxy and Target should be administered under different trust domains. One provider administrator able to inspect both services can still correlate traffic. ODoH does not hide timing/volume or the Target's view of the Proxy IP.

This is not a security audit or a claim of full RFC 9230 conformance. The ODoH library is archived; test vectors, fuzzing, and end-to-end compatibility checks remain necessary. Failed remote blocklist refresh keeps the last-known-good list when one exists. The archived parser also requires independent review; the Target now recovers per request from parser panics, but that is defense-in-depth, not a substitute for replacing the dependency.
