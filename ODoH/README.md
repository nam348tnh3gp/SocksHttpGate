# SocksHttpGate ODoH — Proxy + Target servers

[![ODoH CI](https://img.shields.io/github/actions/workflow/status/nam348tnh3gp/SocksHttpGate/odoh.yml?branch=main&style=for-the-badge&label=ODoH%20CI)](https://github.com/nam348tnh3gp/SocksHttpGate/actions/workflows/odoh.yml)
[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![Protocol](https://img.shields.io/badge/Protocol-RFC%209230%20ODoH-6f42c1?style=for-the-badge)](https://www.rfc-editor.org/rfc/rfc9230)
[![Docker build](https://img.shields.io/badge/Docker-Proxy%20%2B%20Target-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://github.com/nam348tnh3gp/SocksHttpGate/actions/workflows/odoh.yml)
[![Tests](https://img.shields.io/badge/Tests-Protocol%20%2B%20Race%20%2B%20Fuzzing-success?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate/actions/workflows/odoh.yml)
[![Status](https://img.shields.io/badge/Status-Experimental-orange?style=for-the-badge)](#security-and-production-readiness)
[![Security](https://img.shields.io/badge/Security-Review%20before%20production-critical?style=for-the-badge)](#security-and-production-readiness)
[![Last commit](https://img.shields.io/github/last-commit/nam348tnh3gp/SocksHttpGate/main/ODoH?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate/commits/main/ODoH)
[![License](https://img.shields.io/github/license/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](../LICENSE)

SocksHttpGate ODoH includes **its own Go Proxy and Target server implementations** and protocol-level tests. It is not limited to the legacy reference-server harness in `run.sh`.

## Components

- **Proxy** — `Proxy/`: accepts ODoH HTTP requests, forwards opaque encrypted messages to the configured Target, and exposes health/status/statistics endpoints.
- **Target** — `Target/`: publishes ODoH public configuration at `/.well-known/odohconfigs`, processes encrypted ODoH queries, applies the configured blocklist, forwards DNS resolution to an upstream DoH resolver, and returns encrypted responses.
- **Protocol tests** — the Go tests exercise ODoH configuration retrieval and decoding, query encryption, request handling, response decryption and DNS answer validation, blocklist behavior, malformed input handling, and fuzz cases.
- **Deployment** — separate Docker build definitions and `render.yaml` are provided for Proxy and Target.

## Run protocol tests

Install Go 1.23 or newer, then run the tests for both services:

```sh
cd ODoH/Proxy
go test ./...
cd ../Target
go test ./...
```

Some integration tests contact the real upstream Cloudflare DoH endpoint, so those tests require working network access and may fail if the upstream service or network is unavailable. To include race detection:

```sh
go test -race ./...
```

Run these commands separately in `Proxy/` and `Target/`.

## Deployment overview

Deploy Proxy and Target as separate services. Configure the Proxy with the Target's reachable URL and configure the Target with its upstream DoH resolver, key material, and blocklist settings as supported by each service. Keep Target private-key material on the Target only. Ensure the Proxy can reach the Target over the deployment network, and verify the configured URL scheme and TLS behavior against the actual service configuration before deployment.

A passing protocol test demonstrates that the exercised ODoH query path works in the test environment; it does not by itself establish a complete RFC 9230 conformance audit or a production security audit.

## Security and production readiness

- Treat the service as experimental until deployment configuration, access controls, key management, resource limits, logging behavior, and the full Proxy–Target trust separation have been reviewed.
- Keep the Target private key out of the Proxy environment and restrict Target access to the intended Proxy.
- Avoid logging DNS payloads or other data that could undermine user privacy.
- Test against published RFC 9230 vectors and perform independent security review before handling sensitive or production traffic.
- The legacy `run.sh` script is a **separate local interoperability harness**: it downloads the archived Cloudflare reference server and client. It is not the implementation used by the Go servers in `Proxy/` and `Target/`. The script itself warns against exposing that legacy reference server to an untrusted network.

## Legacy reference harness (optional)

The script requires Termux and downloads/builds the archived reference implementation:

```sh
pkg update
pkg install git golang openssl curl
chmod +x run.sh
ALLOW_LEGACY_REFERENCE=YES ./run.sh
```

Optional parameters:

```sh
ALLOW_LEGACY_REFERENCE=YES DOMAIN=cloudflare.com TYPE=AAAA PORT=4567 ./run.sh
```

This optional harness is for local experimentation only; its security limitations do not describe or replace the separate Go Proxy/Target implementation.
