SocksHttpGate — Universal Proxy Suite

￼ ￼

￼ ￼ ￼ ￼ ￼ ￼ ￼ ￼ ￼ ￼

Languages

￼ ￼ ￼ ￼ ￼ ￼ ￼ ￼

Protocols & Technologies

￼ ￼ ￼ ￼ ￼ ￼

SocksHttpGate is a multi-language proxy suite with separate implementations and standalone DNS services. The repository brings together proxy implementations in Python, Go, C, JavaScript, Java, Kotlin, Ruby, and Elixir, alongside independent DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and experimental Oblivious DNS-over-HTTPS (ODoH) components.

The components are maintained separately. Their configuration options, supported features, dependencies, and deployment requirements may differ.

Table of Contents

Features

Repository Structure

Requirements

Getting Started

Proxy Usage

DNS Services 

DNS-over-HTTPS (DoH)

DNS-over-TLS (DoT)

Oblivious DNS-over-HTTPS (ODoH)

Configuration and Deployment

Testing and CI

Security

Troubleshooting

Contributing

License

Features

Proxy Suite

Multiple language implementations — choose an implementation compatible with your runtime and environment.

SOCKS5 and HTTP proxying — available capabilities depend on the selected implementation.

Authentication — username/password authentication where implemented.

Upstream proxy support — supported upstream protocols vary by implementation.

Connection monitoring — logging, connection statistics, and traffic information where implemented.

Access control — connection limits and allow/deny rules where supported.

Flexible deployment — run a compatible implementation on your local machine or server.

DNS Services

DoH: DNS queries over HTTPS through a standalone Go resolver.

DoT: DNS queries over TLS with upstream certificate verification and blocklist support.

ODoH: separate Proxy, Target, and integration components for development and testing.

Blocklists: configurable domain-blocking support in the DNS services that implement it.

Independent services: DNS components do not automatically become the DNS backend for every proxy implementation.

Repository Structure

DirectoryDescriptionGocodeBeta/Go proxy implementationCcodeBeta/C proxy implementationJScodeBeta/JavaScript proxy implementationJavacodeBeta/Java proxy implementationKotlincodeBeta/Kotlin proxy implementationRubycodeBeta/Ruby proxy implementationElixircodeBeta/Elixir proxy implementationDoH/Standalone Go DNS-over-HTTPS serviceDoT/Standalone Go DNS-over-TLS service and dashboardODoH/Proxy/ODoH Proxy componentODoH/Target/ODoH Target componentODoH/integration/ODoH integration tests.github/workflows/GitHub Actions workflows 

Consult the current repository tree for the exact entry point, build command, and configuration of each implementation.

Requirements

Install the toolchain required by the component you want to run.

ComponentTypical requirementsPythonPython 3 and required packagesGoGo toolchain and dependencies declared in go.modCC compiler and required librariesJavaCompatible JDKKotlinCompatible Kotlin compiler/runtimeJavaScriptNode.js and required packagesRubyRuby and required gemsElixirElixir and Erlang/OTPDoHGo toolchain and DoH module dependenciesDoTGo toolchain, module dependencies, TLS certificate and keyODoHGo toolchain and dependencies specified by the individual ODoH modules 

Check each component's README and build files for the required versions. Do not assume that all language implementations use the same flags or configuration format.

Getting Started

Clone the repository:

git clone https://github.com/nam348tnh3gp/SocksHttpGate.git cd SocksHttpGate 

Choose the component you want to run and inspect its documentation and source files.

For Termux, install the tools required by your chosen component. For Go-based components, a typical starting point is:

pkg update pkg install git golang 

Follow the build and launch instructions for that component. Commands and dependencies may differ across directories.

Termux Notes

Install only the dependencies required by the component you intend to use.

Confirm the device architecture and available runtime versions.

Keep long-running services in a trusted environment.

Android may stop background processes because of battery optimization or system restrictions.

Proxy Usage

SocksHttpGate contains separate proxy implementations. Review the selected implementation before launching it.

Before using a proxy:

Identify its supported protocols and listening port.

Check whether authentication is enabled.

Review upstream proxy and access-control settings.

Bind to a suitable network interface.

Test the connection with a trusted destination.

Example HTTP proxy test, assuming an HTTP proxy is configured on localhost port 1080:

curl -x http://127.0.0.1:1080 https://example.com/ 

Example SOCKS5 test, if supported by the selected implementation:

curl --socks5-hostname 127.0.0.1:1080 https://example.com/ 

Change the address, port, and authentication parameters to match your configuration. These examples are connection tests, not a guarantee that every implementation supports the same options.

DNS Services

DNS-over-HTTPS (DoH)

The standalone DoH service is located in DoH/.

It provides DNS resolution over HTTPS and supports a configurable upstream DoH endpoint. The current implementation also includes health, statistics, logging, and runtime configuration endpoints.

EndpointPurpose/Web dashboard/healthHealth check/dns-queryDoH query endpoint/api/statsResolver statistics/api/logs?type=queryQuery log access/api/logs?type=systemSystem log access/api/upstreamRuntime upstream configuration endpoint 

Check DoH/README.md, DoH/main.go, and the deployment files for the exact request format, environment variables, and build instructions.

Android compatibility: Android's built-in Private DNS setting expects a DoT hostname, not a DoH URL. To use DoH, configure a compatible DNS client or application.

The DoH service is separate from the proxy implementations. Do not assume proxy DNS lookups are routed through it unless that integration is explicitly configured and tested.

DNS-over-TLS (DoT)

The standalone DoT resolver is located in DoT/.

Its documented features include:

DNS queries over TLS.

Upstream TLS certificate and hostname verification.

Domain blocklist support.

Query statistics and logs.

A local dashboard and runtime blocklist management.

See DoT/README.md for configuration details, including:

DOT_ADDR

TLS_CERT_FILE

TLS_KEY_FILE

UPSTREAM_DOT

UPSTREAM_TLS_NAME

BLOCKLIST

BLOCKLIST_URLS

BLOCKLIST_REFRESH

DASHBOARD_ADDR

Deployment requirements: Android Private DNS needs a hostname with a valid TLS certificate. The hosting platform must accept inbound TCP traffic on port 853. Some HTTP-only hosting services do not expose arbitrary TCP ports; use a compatible VPS or another platform with raw TCP ingress.

Keep production private keys out of source control. Bind the dashboard to localhost or a trusted private network unless remote access has been secured.

Oblivious DNS-over-HTTPS (ODoH)

The ODoH components are located in ODoH/.

ComponentPurposeODoH/Proxy/ODoH Proxy implementationODoH/Target/ODoH Target implementationODoH/integration/Integration and interoperability tests 

ODoH is designed to separate the client-facing Proxy from the DNS-resolving Target. When correctly implemented and deployed, this separation is intended to reduce the ability of one party to link a client's identity with its DNS queries.

Experimental status: treat the current ODoH implementation as experimental until the code, dependencies, protocol conformance, and deployment security have been independently reviewed.

Before testing, read ODoH/README.md and follow its setup instructions. Do not use an experimental deployment for sensitive or production DNS traffic.

A successful build or smoke test does not by itself prove full RFC 9230 conformance, privacy guarantees, or production readiness. In particular, the Proxy and Target trust boundary, Target destination restrictions, query logging, key handling, and network exposure need careful review.

Configuration and Deployment

Configuration varies by component. Before deployment:

Read the documentation for the selected directory.

Confirm the runtime and dependency versions.

Set an explicit listening address and port.

Enable authentication and access restrictions where available.

Review dashboard and management API exposure.

Confirm that the hosting platform supports the required protocols and ports.

Test with non-sensitive traffic before relying on the service.

An HTTPS website deployment does not automatically provide support for arbitrary TCP services such as DoT on port 853.

Testing and CI

The repository includes GitHub Actions workflows for selected components.

ODoH workflow: .github/workflows/odoh.yml

DoT workflow: .github/workflows/test-dot.yml

Inspect the workflow files and their latest run logs for the checks actually performed. Each component should be tested independently.

Passing CI tests only confirms the behaviors covered by those tests. It does not establish that all language implementations, hosting environments, or production configurations are correct.

Security

Proxy and DNS services can expose your network, traffic metadata, and upstream configuration if they are misconfigured.

Avoid public unauthenticated proxies. Enable strong authentication wherever supported.

Limit network exposure. Bind local-only services to 127.0.0.1 and use firewall rules for remote deployments.

Protect dashboards and APIs. Verify authentication and restrict management endpoints to trusted users or networks.

Secure upstream settings. Use trusted upstream proxy and DNS endpoints.

Protect credentials and keys. Never commit passwords, tokens, or production private keys.

Keep dependencies updated. Review dependency changes and run the available tests.

Review logs. Avoid exposing sensitive query information or credentials.

Review ODoH separately. Test its Proxy/Target separation and security assumptions before any public deployment.

Respect network policies. Use the software only on networks and systems you are authorized to access.

Security features differ between implementations. Review the source and test the exact configuration you plan to deploy.

Troubleshooting

ProblemThings to checkBuild failsRuntime version, module dependencies, compiler and build instructionsPort is already in useExisting process and configured listening portProxy authentication failsCredentials and authentication configurationProxy connects but traffic failsDNS resolution, upstream connectivity, routing, and CONNECT handlingDoH requests failRequest format, upstream availability, service logs, and blocklist initializationDoT connection failsTCP port 853, firewall rules, certificate validity, and hostname matchingDashboard is unreachableDashboard address, port, and network restrictionsODoH integration failsProxy/Target configuration, test output, and workflow logs 

Contributing

Contributions, bug reports, fixes, and documentation improvements are welcome.

When opening an issue, include:

The component and directory involved.

Operating system and runtime versions.

Steps to reproduce the problem.

Expected and actual behavior.

Relevant logs with secrets and sensitive data removed.

Please test changes for the affected component before submitting them.

License

This repository contains a LICENSE file. Read it for the applicable license terms before redistributing or modifying the project.

