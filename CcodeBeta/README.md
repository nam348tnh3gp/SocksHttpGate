# C proxy

Standalone C implementation of the SocksHttpGate proxy, including SOCKS5 TCP/UDP and HTTP CONNECT features. It has its own runtime/configuration and is not a wrapper around the Go implementation.

## Requirements

- GCC or another compatible C compiler.
- POSIX/Linux networking and pthread support.

## Build and run

```sh
gcc -O2 -pthread -o proxy proxy.c
./proxy --help
./proxy -l 127.0.0.1 -p 1080 --dashboard-bind 127.0.0.1 --dashboard-port 8081
```

The source documents the JSON configuration files `proxy_config.json` and `proxy_usage.json`. Consult `./proxy --help` and the source before using additional options; do not assume configuration parity with other language ports.

## Test

There is no language-specific automated test command documented in this folder. At minimum, compile with warnings enabled during development:

```sh
gcc -Wall -Wextra -O2 -pthread -o proxy proxy.c
./proxy --help
```

Then test only against a local instance and a target you control.

## Security

The proxy may expose a listener and a management dashboard. Bind to localhost for development, configure authentication/allow-lists where appropriate, and restrict dashboard access. Review generated JSON/config files for credentials and usage data before sharing them.
