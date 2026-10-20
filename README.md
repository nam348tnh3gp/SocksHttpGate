SocksHttpGate — Universal Proxy Suite

"Version" (https://img.shields.io/badge/Version-6.3-blue?style=for-the-badge)
"License" (https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

"GitHub Stars" (https://img.shields.io/github/stars/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=github)
"GitHub Forks" (https://img.shields.io/github/forks/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=github)
"GitHub Watchers" (https://img.shields.io/github/watchers/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=github)
"Contributors" (https://img.shields.io/github/contributors/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=github)
"Repository Size" (https://img.shields.io/github/repo-size/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=github)
"Last Commit" (https://img.shields.io/github/last-commit/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=git)
"Commit Activity" (https://img.shields.io/github/commit-activity/m/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=git)
"Open Issues" (https://img.shields.io/github/issues/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=github)
"Closed Issues" (https://img.shields.io/github/issues-closed/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=github)
"Pull Requests" (https://img.shields.io/github/issues-pr/nam348tnh3gp/SocksHttpGate?style=for-the-badge&logo=github)

Languages

"Python" (https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
"Go" (https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
"C" (https://img.shields.io/badge/C-A8B9CC?style=for-the-badge&logo=c&logoColor=black)
"JavaScript" (https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
"Java" (https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)
"Kotlin" (https://img.shields.io/badge/Kotlin-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white)
"Ruby" (https://img.shields.io/badge/Ruby-CC342D?style=for-the-badge&logo=ruby&logoColor=white)
"Elixir" (https://img.shields.io/badge/Elixir-4B275F?style=for-the-badge&logo=elixir&logoColor=white)

Protocols & Technologies

"SOCKS5" (https://img.shields.io/badge/SOCKS5-Proxy-2563EB?style=for-the-badge)
"HTTP Proxy" (https://img.shields.io/badge/HTTP-Proxy-0EA5E9?style=for-the-badge)
"DNS over HTTPS" (https://img.shields.io/badge/DNS-over_HTTPS-16A34A?style=for-the-badge)
"DNS over TLS" (https://img.shields.io/badge/DNS-over_TLS-0F766E?style=for-the-badge)
"ODoH" (https://img.shields.io/badge/ODoH-Oblivious_DNS-8B5CF6?style=for-the-badge)
"GitHub" (https://img.shields.io/badge/Hosted_on-GitHub-181717?style=for-the-badge&logo=github&logoColor=white)

---

SocksHttpGate is a multi-language proxy suite with separate implementations and standalone DNS services. The repository brings together proxy implementations in Python, Go, C, JavaScript, Java, Kotlin, Ruby, and Elixir, alongside independent DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and experimental Oblivious DNS-over-HTTPS (ODoH) components.

The components are maintained separately. Their configuration options, supported features, dependencies, and deployment requirements may differ.

Table of Contents

- "Features" (#features)
- "Repository Structure" (#repository-structure)
- "Requirements" (#requirements)
- "Getting Started" (#getting-started)
- "Proxy Usage" (#proxy-usage)
- "DNS Services" (#dns-services)
  - "DNS-over-HTTPS (DoH)" (#dns-over-https-doh)
  - "DNS-over-TLS (DoT)" (#dns-over-tls-dot)
  - "Oblivious DNS-over-HTTPS (ODoH)" (#oblivious-dns-over-https-odoh)
- "Configuration and Deployment" (#configuration-and-deployment)
- "Testing and CI" (#testing-and-ci)
- "Security" (#security)
- "Troubleshooting" (#troubleshooting)
- "Contributing" (#contributing)
- "License" (#license)

Features

Proxy Suite

- Multiple language implementations — choose an implementation compatible with your runtime and environment.
- SOCKS5 and HTTP proxying — available capabilities depend on the selected implementation.
- Authentication — username/password authentication where implemented.
- Upstream proxy support — supported upstream protocols vary by implementation.
- Connection monitoring — logging, connection statistics, and traffic information where implemented.
- Access control — connection limits and allow/deny rules where supported.
- Flexible deployment — run a compatible implementation on your local machine or server.

DNS Services

- DoH: DNS queries over HTTPS through a standalone Go resolver.
- DoT: DNS queries over TLS with upstream certificate verification and blocklist support.
- ODoH: separate Proxy, Target, and integration components for development and testing.
- Blocklists: configurable domain-blocking support in the DNS services that implement it.
- Independent services: DNS components do not automatically become the DNS backend for every proxy implementation.

Repository Structure

Directory| Description
"GocodeBeta/"| Go proxy implementation
"CcodeBeta/"| C proxy implementation
"JScodeBeta/"| JavaScript proxy implementation
"JavacodeBeta/"| Java proxy implementation
"KotlincodeBeta/"| Kotlin proxy implementation
"RubycodeBeta/"| Ruby proxy implementation
"ElixircodeBeta/"| Elixir proxy implementation
"DoH/"| Standalone Go DNS-over-HTTPS service
"DoT/"| Standalone Go DNS-over-TLS service and dashboard
"ODoH/Proxy/"| ODoH Proxy component
"ODoH/Target/"| ODoH Target component
"ODoH/integration/"| ODoH integration tests
".github/workflows/"| GitHub Actions workflows

Consult the current repository tree for the exact entry point, build command, and configuration of each implementation.

Requirements

Install the toolchain required by the component you want to run.

Component| Typical requirements
Python| Python 3 and required packages
Go| Go toolchain and dependencies declared in "go.mod"
C| C compiler and required libraries
Java| Compatible JDK
Kotlin| Compatible Kotlin compiler/runtime
JavaScript| Node.js and required packages
Ruby| Ruby and required gems
Elixir| Elixir and Erlang/OTP
DoH| Go toolchain and DoH module dependencies
DoT| Go toolchain, module dependencies, TLS certificate and key
ODoH| Go toolchain and dependencies specified by the individual ODoH modules

Check each component's README and build files for the required versions. Do not assume that all language implementations use the same flags or configuration format.

Getting Started

Clone the repository:

git clone https://github.com/nam348tnh3gp/SocksHttpGate.git
cd SocksHttpGate

Choose the component you want to run and inspect its documentation and source files.

For Termux, install the tools required by your chosen component. For Go-based components, a typical starting point is:

pkg update
pkg install git golang

Follow the build and launch instructions for that component. Commands and dependencies may differ across directories.

Termux Notes

- Install only the dependencies required by the component you intend to use.
- Confirm the device architecture and available runtime versions.
- Keep long-running services in a trusted environment.
- Android may stop background processes because of battery optimization or system restrictions.

Proxy Usage

SocksHttpGate contains separate proxy implementations. Review the selected implementation before launching it.

Before using a proxy:

1. Identify its supported protocols and listening port.
2. Check whether authentication is enabled.
3. Review upstream proxy and access-control settings.
4. Bind to a suitable network interface.
5. Test the connection with a trusted destination.

Example HTTP proxy test, assuming an HTTP proxy is configured on localhost port "1080":

curl -x http://127.0.0.1:1080 https://example.com/

Example SOCKS5 test, if supported by the selected implementation:

curl --socks5-hostname 127.0.0.1:1080 https://example.com/

Change the address, port, and authentication parameters to match your configuration. These examples are connection tests, not a guarantee that every implementation supports the same options.

DNS Services

DNS-over-HTTPS (DoH)

The standalone DoH service is located in "DoH/".

It provides DNS resolution over HTTPS and supports a configurable upstream DoH endpoint. The current implementation also includes health, statistics, logging, and runtime configuration endpoints.

Endpoint| Purpose
"/"| Web dashboard
"/health"| Health check
"/dns-query"| DoH query endpoint
"/api/stats"| Resolver statistics
"/api/logs?type=query"| Query log access
"/api/logs?type=system"| System log access
"/api/upstream"| Runtime upstream configuration endpoint

Check "DoH/README.md", "DoH/main.go", and the deployment files for the exact request format, environment variables, and build instructions.

Android compatibility: Android's built-in Private DNS setting expects a DoT hostname, not a DoH URL. To use DoH, configure a compatible DNS client or application.

The DoH service is separate from the proxy implementations. Do not assume proxy DNS lookups are routed through it unless that integration is explicitly configured and tested.

DNS-over-TLS (DoT)

The standalone DoT resolver is located in "DoT/".

Its documented features include:

- DNS queries over TLS.
- Upstream TLS certificate and hostname verification.
- Domain blocklist support.
- Query statistics and logs.
- A local dashboard and runtime blocklist management.

See ""DoT/README.md"" (DoT/README.md) for configuration details, including:

- "DOT_ADDR"
- "TLS_CERT_FILE"
- "TLS_KEY_FILE"
- "UPSTREAM_DOT"
- "UPSTREAM_TLS_NAME"
- "BLOCKLIST"
- "BLOCKLIST_URLS"
- "BLOCKLIST_REFRESH"
- "DASHBOARD_ADDR"

Deployment requirements: Android Private DNS needs a hostname with a valid TLS certificate. The hosting platform must accept inbound TCP traffic on port "853". Some HTTP-only hosting services do not expose arbitrary TCP ports; use a compatible VPS or another platform with raw TCP ingress.

Keep production private keys out of source control. Bind the dashboard to localhost or a trusted private network unless remote access has been secured.

Oblivious DNS-over-HTTPS (ODoH)

The ODoH components are located in "ODoH/".

Component| Purpose
"ODoH/Proxy/"| ODoH Proxy implementation
"ODoH/Target/"| ODoH Target implementation
"ODoH/integration/"| Integration and interoperability tests

ODoH is designed to separate the client-facing Proxy from the DNS-resolving Target. When correctly implemented and deployed, this separation is intended to reduce the ability of one party to link a client's identity with its DNS queries.

Experimental status: treat the current ODoH implementation as experimental until the code, dependencies, protocol conformance, and deployment security have been independently reviewed.

Before testing, read ""ODoH/README.md"" (ODoH/README.md) and follow its setup instructions. Do not use an experimental deployment for sensitive or production DNS traffic.

A successful build or smoke test does not by itself prove full RFC 9230 conformance, privacy guarantees, or production readiness. In particular, the Proxy and Target trust boundary, Target destination restrictions, query logging, key handling, and network exposure need careful review.

Configuration and Deployment

Configuration varies by component. Before deployment:

1. Read the documentation for the selected directory.
2. Confirm the runtime and dependency versions.
3. Set an explicit listening address and port.
4. Enable authentication and access restrictions where available.
5. Review dashboard and management API exposure.
6. Confirm that the hosting platform supports the required protocols and ports.
7. Test with non-sensitive traffic before relying on the service.

An HTTPS website deployment does not automatically provide support for arbitrary TCP services such as DoT on port "853".

Testing and CI

The repository includes GitHub Actions workflows for selected components.

- ODoH workflow: ".github/workflows/odoh.yml"
- DoT workflow: ".github/workflows/test-dot.yml"

Inspect the workflow files and their latest run logs for the checks actually performed. Each component should be tested independently.

Passing CI tests only confirms the behaviors covered by those tests. It does not establish that all language implementations, hosting environments, or production configurations are correct.

Security

Proxy and DNS services can expose your network, traffic metadata, and upstream configuration if they are misconfigured.

- Avoid public unauthenticated proxies. Enable strong authentication wherever supported.
- Limit network exposure. Bind local-only services to "127.0.0.1" and use firewall rules for remote deployments.
- Protect dashboards and APIs. Verify authentication and restrict management endpoints to trusted users or networks.
- Secure upstream settings. Use trusted upstream proxy and DNS endpoints.
- Protect credentials and keys. Never commit passwords, tokens, or production private keys.
- Keep dependencies updated. Review dependency changes and run the available tests.
- Review logs. Avoid exposing sensitive query information or credentials.
- Review ODoH separately. Test its Proxy/Target separation and security assumptions before any public deployment.
- Respect network policies. Use the software only on networks and systems you are authorized to access.

Security features differ between implementations. Review the source and test the exact configuration you plan to deploy.

Troubleshooting

Problem| Things to check
Build fails| Runtime version, module dependencies, compiler and build instructions
Port is already in use| Existing process and configured listening port
Proxy authentication fails| Credentials and authentication configuration
Proxy connects but traffic fails| DNS resolution, upstream connectivity, routing, and CONNECT handling
DoH requests fail| Request format, upstream availability, service logs, and blocklist initialization
DoT connection fails| TCP port "853", firewall rules, certificate validity, and hostname matching
Dashboard is unreachable| Dashboard address, port, and network restrictions
ODoH integration fails| Proxy/Target configuration, test output, and workflow logs

Contributing

Contributions, bug reports, fixes, and documentation improvements are welcome.

When opening an issue, include:

- The component and directory involved.
- Operating system and runtime versions.
- Steps to reproduce the problem.
- Expected and actual behavior.
- Relevant logs with secrets and sensitive data removed.

Please test changes for the affected component before submitting them.

License

This repository contains a "LICENSE" file. Read it for the applicable license terms before redistributing or modifying the project.