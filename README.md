# SocksHttpGate

A multi-language SOCKS5/HTTP proxy project with standalone DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and Oblivious DNS-over-HTTPS (ODoH) services. Each implementation is maintained as a separate component; configuration and security properties are not automatically shared across languages or directories.

> **Important:** The Go ODoH Proxy and Target servers are real separate service implementations with protocol-level tests. `ODoH/run.sh` is a separate optional legacy reference harness; it is not the Go server implementation.

[![GitHub stars](https://img.shields.io/github/stars/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=github)](https://github.com/nam348tnh3gp/SocksHttpGate/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=github)](https://github.com/nam348tnh3gp/SocksHttpGate/forks)
[![Last commit](https://img.shields.io/github/last-commit/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate/commits/main)
[![License](https://img.shields.io/github/license/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](LICENSE)

### DNS CI

[![DoH CI](https://img.shields.io/github/actions/workflow/status/nam348tnh3gp/SocksHttpGate/test-doh.yml?branch=main&style=for-the-badge&label=DoH%20CI)](https://github.com/nam348tnh3gp/SocksHttpGate/actions/workflows/test-doh.yml)
[![DoT CI](https://img.shields.io/github/actions/workflow/status/nam348tnh3gp/SocksHttpGate/test-dot.yml?branch=main&style=for-the-badge&label=DoT%20CI)](https://github.com/nam348tnh3gp/SocksHttpGate/actions/workflows/test-dot.yml)
[![ODoH CI](https://img.shields.io/github/actions/workflow/status/nam348tnh3gp/SocksHttpGate/odoh.yml?branch=main&style=for-the-badge&label=ODoH%20CI)](https://github.com/nam348tnh3gp/SocksHttpGate/actions/workflows/odoh.yml)

[![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Go](https://img.shields.io/badge/Go-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev/)
[![C](https://img.shields.io/badge/C-A8B9CC?style=flat&logo=c&logoColor=black)](https://en.cppreference.com/w/c)
[![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Java](https://img.shields.io/badge/Java-ED8B00?style=flat&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Kotlin](https://img.shields.io/badge/Kotlin-7F52FF?style=flat&logo=kotlin&logoColor=white)](https://kotlinlang.org/)
[![Ruby](https://img.shields.io/badge/Ruby-CC342D?style=flat&logo=ruby&logoColor=white)](https://www.ruby-lang.org/)
[![Elixir](https://img.shields.io/badge/Elixir-4B275F?style=flat&logo=elixir&logoColor=white)](https://elixir-lang.org/)

## Contents

- [Components](#components)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [DNS services](#dns-services)
- [Testing and CI](#testing-and-ci)
- [Security and deployment](#security-and-deployment)
- [Troubleshooting](#troubleshooting)

## Components

| Path | Component | Documentation |
| --- | --- | --- |
| `server.py` | Python SOCKS5/HTTP proxy server, dashboard and configuration | This README; run `python3 server.py --help` |
| `udp.py` | SOCKS5 UDP monitoring/probing tool (STUN/WireGuard and metrics features) | This README; run `python3 udp.py --help` |
| `test.py` | SOCKS5 UDP relay test client; requires a running proxy | This README; run `python3 test.py --help` |
| `check.py` | Go source validity checker; uses Go tooling when available and otherwise has a heuristic mode | Run `python3 check.py --help` |
| `GocodeBeta/` | Go SOCKS5/HTTP proxy | [README](GocodeBeta/README.md) |
| `CcodeBeta/` | C SOCKS5/HTTP proxy | [README](CcodeBeta/README.md) |
| `JScodeBeta/` | Node.js SOCKS5/HTTP proxy | [README](JScodeBeta/README.md) |
| `JavacodeBeta/` | Java proxy (Java 21 recommended) | [README](JavacodeBeta/README.md) |
| `KotlincodeBeta/` | Kotlin proxy | [README](KotlincodeBeta/README.md) |
| `RubycodeBeta/` | Ruby proxy | [README](RubycodeBeta/README.md) |
| `ElixircodeBeta/` | Elixir proxy | [README](ElixircodeBeta/README.md) |
| `DoH/` | Standalone Go DNS-over-HTTPS service and dashboard | [README](DoH/README.md) |
| `DoT/` | Standalone Go DNS-over-TLS service and dashboard | [README](DoT/README.md) |
| `ODoH/Proxy/` | ODoH HTTP Proxy service | [ODoH README](ODoH/README.md) |
| `ODoH/Target/` | ODoH Target service; key material belongs here only | [ODoH implementation notes](ODoH/README-IMPLEMENTATION.md) |
| `ODoH/run.sh` | Optional legacy reference interoperability harness | [ODoH README](ODoH/README.md) |

These are separate programs, not one unified executable. DoH/DoT/ODoH are not automatically wired into every SOCKS5/HTTP proxy implementation. Verify a specific integration in that component's source and tests before relying on it.

## Requirements

Install only what your selected component needs:

- Python: Python 3; see `requirements.txt` for optional/runtime packages.
- Go: version declared in the selected folder's `go.mod` (DoH/DoT/ODoH require Go 1.23+).
- C: GCC/compatible compiler and pthread support.
- Node.js: supported Node runtime.
- Java: JDK 21 recommended.
- Kotlin: Kotlin compiler and JDK.
- Ruby: Ruby runtime.
- Elixir: Elixir and Erlang/OTP.
- Docker: only for container builds/deployments.

## Quick start

```sh
git clone https://github.com/nam348tnh3gp/SocksHttpGate.git
cd SocksHttpGate
```

Python proxy:

```sh
python3 server.py --help
python3 server.py --listen 127.0.0.1 --port 1080
```

Check exact options and configure credentials/dashboard access before use. For other implementations, open the linked component README first.

For a local HTTP proxy on port 1080, a basic client check is:

```sh
curl -x http://127.0.0.1:1080 https://example.com/
```

For a SOCKS5-capable implementation:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

Add the authentication flags supported by your selected implementation if enabled. These are connection examples, not a guarantee that every build has identical options.

## DNS services

### DoH — DNS over HTTPS

The Go service in [`DoH/`](DoH/) accepts DNS wire-format messages at `POST /dns-query` with `Content-Type: application/dns-message`. It also provides `/health` and a web dashboard/API. Deploy it as a separate HTTPS service; see [DoH/README.md](DoH/README.md) for variables, blocklists, Docker and Render.

Android's built-in Private DNS setting expects a DoT provider hostname, not a DoH URL. For DoH, use a compatible DNS client/app that accepts a custom URL.

### DoT — DNS over TLS

The Go service in [`DoT/`](DoT/) listens on TCP port 853 by default and verifies the upstream TLS server. It supports blocklists and a dashboard. It requires a server certificate/key and a host that permits inbound raw TCP 853; see [DoT/README.md](DoT/README.md).

Keep the dashboard bound to localhost by default: its API does not provide authentication.

### ODoH — Oblivious DNS over HTTPS

[`ODoH/Proxy/`](ODoH/Proxy/) and [`ODoH/Target/`](ODoH/Target/) are separate Go services. The Proxy forwards opaque encrypted ODoH requests to the Target; the Target publishes ODoH configuration, decrypts requests, applies its blocklist, resolves allowed queries using upstream DoH, and encrypts responses. The tests cover configuration retrieval, encrypted query/response processing, DNS answer validation, blocklist behavior, malformed inputs and related regressions. Some integration tests require outbound HTTPS access to Cloudflare DoH.

Read [ODoH/README.md](ODoH/README.md) and [ODoH/README-IMPLEMENTATION.md](ODoH/README-IMPLEMENTATION.md) for local tests, environment variables, Render deployment and limitations. The optional `ODoH/run.sh` is a separate archived reference harness and is not the native Go Proxy/Target implementation.

ODoH is still experimental: passing the current tests does not constitute a complete RFC 9230 conformance or production security audit. Keep Target private-key material on Target only, maintain trust separation between Proxy and Target, and review the archived ODoH library dependency before production use.

## Testing and CI

GitHub Actions workflows:

- [DoH CI](.github/workflows/test-doh.yml): formatting, module consistency, tests, vet, build, Docker build and local HTTP/DNS endpoint smoke test.
- [DoT CI](.github/workflows/test-dot.yml): formatting, module consistency, unit tests, vet, build, Docker build, DoT query and dashboard smoke test.
- [ODoH CI](.github/workflows/odoh.yml): formatting, module consistency, vet, builds, race-enabled protocol/regression tests, bounded fuzzing and both Docker builds.

Workflows run for component changes and pull requests, and can be started manually. ODoH and DoH integration checks that resolve public names require working outbound network access; external resolver outages can cause failures unrelated to a local compile error.

Run checks from the relevant component directory. For Go modules:

```sh
go test ./...
go vet ./...
go build ./...
```

Use the workflow corresponding to the component for its full test procedure. Passing CI only covers tested behavior and is not a security certification.

## Security and deployment

1. Bind proxy listeners and dashboards to localhost during development.
2. Before public exposure, configure authentication and network allow-lists supported by that implementation.
3. Keep management APIs private; DoT dashboard API has no authentication by default.
4. Keep credentials, private keys, key seeds, and runtime usage/config files out of Git.
5. Use trusted upstream proxy and DNS providers and understand that upstreams can observe destination or DNS metadata.
6. Confirm that your host supports the required protocol and ports. HTTP-only hosting usually cannot expose raw TCP 853 for DoT.
7. Test with non-sensitive traffic and review logs for accidental sensitive data.

Use the project only on systems and networks you own or are authorized to access.

## Troubleshooting

| Symptom | Checks |
| --- | --- |
| Proxy starts but requests fail | Listener address, authentication, upstream proxy scheme/handshake, DNS and CONNECT support |
| Port already in use | Existing process and configured port |
| DoH fails | HTTPS endpoint, `/dns-query`, DNS wire format/content type, upstream availability, logs |
| DoT fails | TCP 853 ingress, certificate chain/hostname, server key readability, upstream TLS name |
| ODoH fails | Proxy's Target origin, Target key seed, private network reachability, ODoH content type and workflow logs |
| Dashboard unavailable | Dashboard bind address/port, local firewall and process logs |
| Build fails | Correct directory, language/runtime version, dependency files and compiler |

## Contributing

When reporting an issue, include the component path, OS/runtime version, exact steps, expected and actual results, and relevant logs with secrets removed. Run the component's documented tests before submitting a change.
