# Java proxy

Standalone Java implementation of the SocksHttpGate SOCKS5/HTTP proxy. The source documents Java 21 and virtual-thread support.

## Requirements

- JDK 21 or newer is recommended by the source comments.
- No external Java dependency manager is required by the single-file implementation.

## Run with source-file mode

```sh
java --version
java Proxy.java --help
java Proxy.java -l 127.0.0.1 -p 1080 --dashboard-port 8081
```

Or compile first:

```sh
javac Proxy.java
java Proxy --help
java Proxy -l 127.0.0.1 -p 1080 --dashboard-port 8081
```

The proxy defaults to port `1080` and the dashboard to `8081`. Use `--help` for the complete list of options.

## Test

```sh
javac Proxy.java
java Proxy --help
```

No dedicated automated test suite is defined in this folder. Perform local SOCKS5/HTTP tests against destinations you control.

## Security

Bind to localhost during development. Before public deployment, verify authentication, dashboard access controls, listener binding, and configuration permissions. Never commit passwords, private keys, or runtime usage data.
