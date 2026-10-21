# Elixir proxy

Single-file Elixir implementation of the SocksHttpGate SOCKS5/HTTP proxy.

## Requirements

- Elixir and Erlang/OTP.
- Crypto application support.

## Run

```sh
elixir --version
elixir proxy.exs --help
elixir proxy.exs -l 127.0.0.1 -p 1080 --dashboard-bind 127.0.0.1 --dashboard-port 8081
```

The source comments document proxy port `1080` and dashboard port `8081`. Run `--help` to confirm the full supported option list for the checked-out version.

## Test

```sh
elixir proxy.exs --help
```

No dedicated automated test suite is defined in this folder. Validate SOCKS5/HTTP behavior using a local client and targets you control.

## Security

Bind to localhost during development. Review listener authentication, dashboard binding, and runtime config files before deployment; do not expose management endpoints publicly without appropriate access controls.
