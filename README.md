# SocksHttpGate — Universal Proxy Suite

![Version](https://img.shields.io/badge/Version-6.3-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

## Languages

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![C](https://img.shields.io/badge/C-A8B9CC?style=for-the-badge&logo=c&logoColor=black)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)
![Kotlin](https://img.shields.io/badge/Kotlin-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white)
![Ruby](https://img.shields.io/badge/Ruby-CC342D?style=for-the-badge&logo=ruby&logoColor=white)
![Elixir](https://img.shields.io/badge/Elixir-4B275F?style=for-the-badge&logo=elixir&logoColor=white)

## Protocols and technologies

![SOCKS5](https://img.shields.io/badge/SOCKS5-Proxy-2563EB?style=for-the-badge)
![HTTP Proxy](https://img.shields.io/badge/HTTP-Proxy-0EA5E9?style=for-the-badge)
![DNS over HTTPS](https://img.shields.io/badge/DNS-over_HTTPS-16A34A?style=for-the-badge)
![GitHub](https://img.shields.io/badge/Hosted_on-GitHub-181717?style=for-the-badge&logo=github&logoColor=white)

SocksHttpGate is a multi-language proxy suite with implementations in Python, Go, C, JavaScript, Java, Kotlin, Ruby, and Elixir. The implementations provide SOCKS5 and HTTP proxy functionality, with additional capabilities such as authentication, connection statistics, access rules, upstream proxies, and a management dashboard depending on the implementation and its configuration.

The repository also contains a **separate Go-based DNS-over-HTTPS (DoH) resolver**. The proxy programs do not automatically send their DNS lookups through this DoH service; their DNS behavior depends on each implementation and the host runtime/system configuration.

> **Compatibility note:** The language ports are separate programs, and their options, dependencies, and feature parity can differ. Check the relevant source directory before deploying.

## Repository layout

| Path | Language / component |
| --- | --- |
| `server.py` | Python proxy |
| `GocodeBeta/proxy.go` | Go proxy |
| `CcodeBeta/proxy.c` | C proxy |
| `JScodeBeta/proxy.js` | JavaScript / Node.js proxy |
| `JavacodeBeta/Proxy.java` | Java proxy |
| `KotlincodeBeta/proxy.kt` | Kotlin proxy |
| `RubycodeBeta/proxy.rb` | Ruby proxy |
| `ElixircodeBeta/proxy.exs` | Elixir proxy |
| `DoH/main.go` | Standalone Go DoH resolver |

## Features

Features vary by language port, but the suite includes implementations with the following capabilities:

- **SOCKS5 and HTTP proxying** — supports TCP proxying and HTTP CONNECT; SOCKS5 UDP relay is available in implementations that include it.
- **Proxy authentication** — username/password authentication and configuration-based user settings where implemented.
- **Upstream proxy support** — configurable HTTP CONNECT and/or SOCKS5 upstreams in supported ports.
- **Connection visibility** — active connection information, traffic counters, logs, and statistics where implemented.
- **Access controls** — allow/deny address rules and connection limits in supported implementations.
- **Operational safeguards** — connection timeouts, cleanup, and authentication-failure handling where implemented.
- **Standalone DoH resolver** — DNS-over-HTTPS endpoint, statistics, query/system logs, and configurable upstream DoH URL.
- **Multiple runtimes** — choose the implementation that best matches your operating system and installed toolchain.

## Requirements

Install the runtime and build tools for the implementation you plan to use.

| Implementation | Typical requirements |
| --- | --- |
| Python | Python 3; optional modules may enable additional features |
| Go | A Go toolchain compatible with the source and its module dependencies |
| C | A C compiler and the libraries required by that implementation |
| Java | A compatible JDK; the Java source documents Java 21 usage |
| Kotlin | Kotlin compiler/runtime compatible with the source |
| JavaScript | Node.js compatible with the source |
| Ruby | Ruby compatible with the source |
| Elixir | Elixir and Erlang/OTP compatible with the source |
| DoH | Go toolchain and the dependencies declared by the DoH module |

The examples below use the Python implementation. Other ports may use different flags and build commands; consult their source files and any accompanying project files.

## Quick start: Python

Clone the repository:

```bash
git clone https://github.com/nam348tnh3gp/SocksHttpGate.git
cd SocksHttpGate
```

Check the available options before launching:

```bash
python3 server.py --help
```

A typical launch is:

```bash
python3 server.py
```

To see the options supported by your checked-out version, use `--help`. Configure the listen address, port, authentication, and other settings only with options actually listed by that version.

### Running on Termux

Install Python and Git, then clone the repository:

```bash
pkg update
pkg install python git
git clone https://github.com/nam348tnh3gp/SocksHttpGate.git
cd SocksHttpGate
python server.py --help
```

Keep the process running in a trusted environment. Android may restrict background processes depending on device and battery settings.

## Testing the proxy

Use a local or trusted test server first. Replace the example host, port, and credentials with the values configured for your proxy.

Test an HTTP proxy:

```bash
curl -x http://USER:PASSWORD@127.0.0.1:1080 https://example.com/
```

Test a SOCKS5 proxy with remote hostname resolution, if supported by your selected implementation:

```bash
curl --socks5-hostname USER:PASSWORD@127.0.0.1:1080 https://example.com/
```

If authentication is disabled, remove the credentials from the command. If your proxy listens on a different address or port, update the examples accordingly. A successful TCP connection alone does not prove that proxy authentication, CONNECT tunneling, DNS resolution, or upstream routing works correctly.

## Standalone DNS-over-HTTPS (DoH)

The Go service in `DoH/` is a separate resolver and management service, not a built-in DNS mode shared by every proxy port. Review `DoH/` and its Go module/build files for the exact runtime configuration and deployment requirements.

The service provides these routes in the current implementation:

| Endpoint | Purpose |
| --- | --- |
| `/` | Web dashboard |
| `/health` | Health check |
| `/dns-query` | DNS-over-HTTPS query endpoint |
| `/api/stats` | Resolver statistics |
| `/api/logs?type=query` | Query log download |
| `/api/logs?type=system` | System log download |
| `/api/upstream` | Update the upstream DoH URL at runtime using a POST request |

The DNS endpoint supports standard DoH request formats implemented by the service. For exact request headers, methods, environment variables, and deployment commands, refer to `DoH/main.go` and the files in `DoH/`.

**Important:** changing the DoH upstream through the runtime endpoint is documented by the service as a runtime-only change; it resets when the process restarts unless separately configured in the deployment environment.

## Configuration

Configuration options differ between ports. Before running a service in production:

1. Run the implementation's help command, if available, or inspect its argument parser.
2. Review any configuration JSON and environment variables used by that implementation.
3. Set an explicit listening address and port.
4. Configure authentication and access restrictions where supported.
5. Confirm which dashboard and management endpoints are exposed, and restrict them to trusted users/networks.

Do not assume that a flag or feature available in one language port also exists in another.

## Security

A proxy can expose your network and bandwidth if it is reachable by untrusted users. Apply these precautions:

- **Do not expose an unauthenticated proxy to the public internet.**
- Use strong, unique credentials and enable authentication wherever available.
- Bind to `127.0.0.1` when access should be local-only; use a firewall or private network for remote access.
- Restrict dashboard and management endpoints. Do not assume that a dashboard or runtime configuration API is authenticated unless you have verified the code and deployment.
- Treat upstream proxy and DoH URLs as security-sensitive configuration. Allow only trusted upstreams.
- Keep runtimes and dependencies updated, and test access-control rules before deployment.
- Monitor logs for unexpected clients, repeated authentication failures, and unusual traffic.
- Avoid using this software to bypass network policies or access systems without permission.

Security controls and protections are not identical across all ports. Review and test the selected implementation before relying on it in a public or production environment.

## Troubleshooting

- **Address already in use:** choose an unused port or stop the process already listening on it.
- **Authentication fails:** check the configured username/password and whether authentication is enabled in that implementation.
- **Proxy connects but websites do not load:** test DNS resolution, the target's reachability, CONNECT handling, and any configured upstream separately.
- **DoH returns an error:** check the service logs, upstream DoH availability, request method/content type, and whether the resolver has completed its initial blocklist loading.
- **Build fails:** verify the required compiler/runtime version and dependencies for the specific directory.
- **Dashboard is unreachable:** confirm the dashboard's configured port and listening address, then check firewall and deployment settings.

## Contributing

Bug reports, fixes, documentation improvements, and carefully tested contributions are welcome. When reporting an issue, include the language implementation, operating system/runtime version, steps to reproduce, expected behavior, and relevant logs. Remove passwords, tokens, private addresses, and other sensitive information before sharing logs.

## License

This project includes a `LICENSE` file. Read that file for the applicable license terms before redistributing or modifying the project.
