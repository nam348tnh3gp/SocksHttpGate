# SocksHttpGate

A multi-language proxy and DNS networking project. The repository contains SOCKS5/HTTP proxy implementations, standalone DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) services, and an experimental Oblivious DNS-over-HTTPS (ODoH) test harness.

> **Status:** Components are maintained independently. Features, configuration, security properties, and deployment requirements vary by directory. Read the component-specific documentation before running or deploying anything.

[![GitHub stars](https://img.shields.io/github/stars/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=github)](https://github.com/nam348tnh3gp/SocksHttpGate/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=github)](https://github.com/nam348tnh3gp/SocksHttpGate/forks)
[![Watchers](https://img.shields.io/github/watchers/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=github)](https://github.com/nam348tnh3gp/SocksHttpGate/watchers)
[![Repo size](https://img.shields.io/github/repo-size/nam348tnh3gp/SocksHttpGate?style=for-the-badge&label=repo%20size)](https://github.com/nam348tnh3gp/SocksHttpGate)
[![Contributors](https://img.shields.io/github/contributors/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate/graphs/contributors)
[![Last commit](https://img.shields.io/github/last-commit/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate/commits/main)
[![Commit activity](https://img.shields.io/github/commit-activity/m/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate/graphs/commit-activity)
[![Open issues](https://img.shields.io/github/issues/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate/issues)
[![Closed issues](https://img.shields.io/github/issues-closed/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate/issues?q=is%3Aissue+is%3Aclosed)
[![Pull requests](https://img.shields.io/github/issues-pr/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate/pulls)
[![License](https://img.shields.io/github/license/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](LICENSE)
[![Top language](https://img.shields.io/github/languages/top/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate)
[![Languages](https://img.shields.io/github/languages/count/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate)

### DNS protocol status

[![DoH](https://img.shields.io/badge/DNS-over--HTTPS-2496ED?style=for-the-badge&logo=cloudflare&logoColor=white)](DoH/)
[![DoT CI](https://img.shields.io/github/actions/workflow/status/nam348tnh3gp/SocksHttpGate/test-dot.yml?branch=main&style=for-the-badge&label=DoT%20CI)](https://github.com/nam348tnh3gp/SocksHttpGate/actions/workflows/test-dot.yml)
[![ODoH CI](https://img.shields.io/github/actions/workflow/status/nam348tnh3gp/SocksHttpGate/odoh.yml?branch=main&style=for-the-badge&label=ODoH%20CI)](https://github.com/nam348tnh3gp/SocksHttpGate/actions/workflows/odoh.yml)

[![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![C](https://img.shields.io/badge/C-A8B9CC?style=for-the-badge&logo=c&logoColor=black)](https://en.cppreference.com/w/c)
[![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/docs/Web/JavaScript)
[![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Kotlin](https://img.shields.io/badge/Kotlin-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white)](https://kotlinlang.org/)
[![Ruby](https://img.shields.io/badge/Ruby-CC342D?style=for-the-badge&logo=ruby&logoColor=white)](https://www.ruby-lang.org/)
[![Elixir](https://img.shields.io/badge/Elixir-4B275F?style=for-the-badge&logo=elixir&logoColor=white)](https://elixir-lang.org/)

## Contents

- [Features](#features)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Proxy testing](#proxy-testing)
- [DNS services](#dns-services)
  - [DoH](#dns-over-https-doh)
  - [DoT](#dns-over-tls-dot)
  - [ODoH](#oblivious-dns-over-https-odoh)
- [Deployment and security](#deployment-and-security)
- [CI and testing](#ci-and-testing)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Multiple implementations:** proxy code in several programming languages.
- **Proxy protocols:** SOCKS5 and HTTP capabilities depend on the chosen implementation.
- **Standalone DNS services:** DoH and DoT have separate implementations and configuration.
- **Blocklists:** DoH and DoT support domain-blocking configuration; details are documented in each directory.
- **ODoH experimentation:** a local interoperability harness based on an archived reference implementation.

The repository is a collection of components, not a single unified executable. A DNS service does not automatically become the DNS backend for every proxy implementation.

## Repository layout

| Path | Purpose |
| --- | --- |
| `server.py`, `udp.py`, `check.py`, `test.py` | Root-level Python programs and tests/utilities |
| `GocodeBeta/` | Go proxy implementation |
| `CcodeBeta/` | C implementation |
| `JScodeBeta/` | JavaScript implementation |
| `JavacodeBeta/` | Java implementation |
| `KotlincodeBeta/` | Kotlin implementation |
| `RubycodeBeta/` | Ruby implementation |
| `ElixircodeBeta/` | Elixir implementation |
| `DoH/` | Standalone Go DNS-over-HTTPS service |
| `DoT/` | Standalone Go DNS-over-TLS service and dashboard |
| `ODoH/` | Local ODoH interoperability test harness |
| `.github/workflows/` | GitHub Actions workflows |

Check each directory for its own README, dependency files, Dockerfile, and configuration. Do not assume commands or options are interchangeable between components.

## Requirements

Install only the toolchain needed for the component you plan to use.

| Component | Typical requirements |
| --- | --- |
| Python | Python 3 and packages listed in `requirements.txt` |
| Go | Go version specified by the component's `go.mod` |
| C | A C compiler and any required system libraries |
| Java | Compatible JDK |
| Kotlin | Kotlin compiler/runtime and any project-specific build tools |
| JavaScript | Node.js and project dependencies |
| Ruby | Ruby and required gems |
| Elixir | Elixir and Erlang/OTP |
| DoH | Go and the dependencies in `DoH/go.mod` |
| DoT | Go 1.23+ and a TLS certificate/key for deployment |
| ODoH harness | Termux or Linux, Go, OpenSSL, and curl |

## Quick start

Clone the repository:

```sh
git clone https://github.com/nam348tnh3gp/SocksHttpGate.git
cd SocksHttpGate
```

On Termux, a starting point for Go-based components is:

```sh
pkg update
pkg install git golang
```

Then enter the component directory and follow its README. For example, the DNS services have separate build and runtime instructions in `DoH/README.md` and `DoT/README.md`.

### Termux notes

- Install dependencies for the selected component, rather than every language toolchain.
- Check your device architecture and runtime versions.
- Android battery management may stop long-running background processes.
- Avoid exposing a local development server to untrusted networks.

## Proxy testing

First inspect the selected implementation's configuration to determine its actual listen address, port, authentication settings, and supported proxy protocols.

For an HTTP proxy listening on localhost port `1080`:

```sh
curl -x http://127.0.0.1:1080 https://example.com/
```

For an implementation that supports SOCKS5:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

These are example connection tests only. Replace the address and port with your configuration, and add authentication options if the implementation requires them.

## DNS services

### DNS-over-HTTPS (DoH)

The standalone Go DoH service is in [`DoH/`](DoH/). See [`DoH/README.md`](DoH/README.md) for deployment instructions and supported configuration.

Typical endpoints documented by this service:

| Endpoint | Purpose |
| --- | --- |
| `/dns-query` | DNS-over-HTTPS query endpoint |
| `/health` | Health check |
| `/` | Web dashboard |

The service uses an upstream DoH resolver and supports blocklist configuration. Consult the component README and source for the current environment variables and runtime API.

**Android:** the built-in Android Private DNS setting expects a DoT provider hostname, not a DoH URL. To use this service, configure a DNS client or app that accepts a custom DoH URL, such as `https://YOUR-SERVICE.onrender.com/dns-query` after deployment.

The DoH service is independent of the proxy implementations. Do not assume proxy DNS requests use it unless that integration is explicitly implemented and tested.

### DNS-over-TLS (DoT)

The standalone DoT service is in [`DoT/`](DoT/). It forwards DNS queries over TLS, verifies the upstream TLS server, supports blocklists, and includes a local dashboard.

Important configuration variables include:

| Variable | Purpose |
| --- | --- |
| `DOT_ADDR` | DoT listener address (default `:853`) |
| `TLS_CERT_FILE` | Server certificate path |
| `TLS_KEY_FILE` | Server private-key path |
| `UPSTREAM_DOT` | Upstream DoT host and port |
| `UPSTREAM_TLS_NAME` | Upstream TLS hostname to verify |
| `BLOCKLIST` | Additional blocked domains |
| `BLOCKLIST_URLS` | Remote blocklist sources |
| `BLOCKLIST_REFRESH` | Remote-list refresh interval |
| `DASHBOARD_ADDR` | Dashboard listen address (default `127.0.0.1:8080`) |

Read [`DoT/README.md`](DoT/README.md) for full instructions, Docker usage, and testing. Android Private DNS requires a hostname covered by a valid certificate. The server must be deployed somewhere that supports inbound **TCP port 853**; typical HTTP-only hosting platforms do not provide arbitrary TCP ingress.

The dashboard API does not provide authentication by default. Keep it bound to localhost or protect it behind a trusted authenticated reverse proxy. Never commit production private keys or certificates.

### Oblivious DNS-over-HTTPS (ODoH)

The [`ODoH/`](ODoH/) directory currently provides a **local interoperability smoke-test harness**, not a production-ready ODoH deployment. Read [`ODoH/README.md`](ODoH/README.md) before running it.

The harness downloads and builds an archived legacy reference implementation and runs a local Proxy/Target test. It requires an explicit acknowledgement before launch:

```sh
cd ODoH
pkg update
pkg install git golang openssl curl
chmod +x run.sh
ALLOW_LEGACY_REFERENCE=YES ./run.sh
```

**Security warning:** the reference implementation is archived and has a publicly reported SSRF concern. Do not expose this harness on a public interface or use it for real or sensitive DNS traffic. A successful smoke test does not prove RFC 9230 conformance, privacy guarantees, or production readiness. See the ODoH README for the limitations and recommended production requirements.

## Deployment and security

Before deploying any component:

1. Read its component-specific documentation and verify its dependencies.
2. Configure an explicit listen address and port.
3. Enable authentication and access restrictions where supported.
4. Keep dashboards and management APIs private unless properly secured.
5. Use trusted upstream proxy and DNS providers.
6. Keep credentials, tokens, and private keys out of version control.
7. Review query logs for sensitive information and limit retention.
8. Confirm that your hosting platform supports the required protocol and network ports.
9. Test with non-sensitive traffic before relying on the service.

A public unauthenticated proxy or management dashboard can be abused. Use this project only on systems and networks you are authorized to access.

## CI and testing

GitHub Actions currently includes workflows for selected components:

- [ODoH validation](.github/workflows/odoh.yml): Go checks, tests, fuzzing, and Docker image builds.
- [DoT tests](.github/workflows/test-dot.yml): formatting, unit tests, vet, build, and a local smoke test.

Run the checks relevant to the component you changed. Passing CI verifies only the behavior covered by those checks; it does not guarantee that every implementation or deployment configuration is secure or correct.

For DoT, the documented local checks are:

```sh
cd DoT
go test ./...
go vet ./...
go build ./...
```

## Troubleshooting

| Problem | Things to check |
| --- | --- |
| Build fails | Correct working directory, Go/runtime version, dependencies, compiler, and build instructions |
| Port is already in use | Existing process and configured listen address |
| Proxy connects but requests fail | Authentication, upstream connectivity, DNS, routing, and CONNECT support |
| DoH requests fail | Correct `/dns-query` URL, request format, upstream availability, and service logs |
| DoT connection fails | TCP port 853, firewall rules, certificate validity, and hostname matching |
| Dashboard is unreachable | Dashboard address, port, and network restrictions |
| ODoH test fails | Harness prerequisites, Proxy/Target setup, test output, and workflow logs |

## Contributing

Bug reports, fixes, tests, and documentation improvements are welcome. When opening an issue, include:

- The affected component and directory.
- Operating system and runtime versions.
- Steps to reproduce the problem.
- Expected and actual behavior.
- Relevant logs with credentials and other sensitive data removed.

Please run the relevant tests before submitting changes.

## License

This repository includes a [`LICENSE`](LICENSE) file. Review it for the applicable terms before redistributing or modifying the project.
