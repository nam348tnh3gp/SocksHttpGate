# JavaScript / Node.js proxy

Single-file Node.js implementation of the SocksHttpGate SOCKS5/HTTP proxy. The source uses Node's built-in networking, TLS, HTTP, and cluster modules.

## Requirements

- A supported Node.js runtime.
- No third-party package installation is indicated by the imports in `proxy.js`.

## Run

```sh
node --version
node proxy.js --help
node proxy.js -l 127.0.0.1 -p 1080 --dashboard-port 8081
```

The source comments document port `1080` for the proxy and `8081` for the dashboard. `WORKERS` can be used to configure the cluster worker count; inspect the source/help output for supported arguments before deployment.

## Test

```sh
node --check proxy.js
node proxy.js --help
```

No dedicated automated unit-test suite is defined in this folder. Verify the proxy using a local client and test targets you control.

## Security

Do not expose an unauthenticated proxy or dashboard to the public internet. Bind to localhost for local use and review authentication, dashboard binding, configuration files, and logs before deployment.
