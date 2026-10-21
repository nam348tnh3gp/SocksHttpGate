# Ruby proxy

Single-file Ruby implementation of the SocksHttpGate SOCKS5/HTTP proxy.

## Requirements

- Ruby.
- The implementation uses Ruby standard libraries; check the source if your Ruby distribution omits any standard component.

## Run

```sh
ruby --version
ruby proxy.rb --help
ruby proxy.rb -l 127.0.0.1 -p 1080 --dashboard-port 8081
```

The documented defaults are proxy port `1080` and dashboard port `8081`. Use `--help` for all supported arguments.

## Test

```sh
ruby -c proxy.rb
ruby proxy.rb --help
```

No dedicated automated unit-test suite is defined in this folder. Test proxy connections locally against destinations you control.

## Security

Keep the listener and dashboard private during development. Before exposing the service, verify authentication, access controls, TLS settings, and file permissions for configuration and usage data.
