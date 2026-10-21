# Go proxy

Standalone Go implementation of the SocksHttpGate SOCKS5/HTTP proxy. This folder is independent from the Go DNS services in `../DoH`, `../DoT`, and `../ODoH`.

## Requirements

- Go version supported by `go.mod` (module declares Go 1.21).
- A free proxy port (default `1080`).
- A free dashboard port (default `8081`).

## Run

From this directory:

```sh
go run . -h
go run . -l 127.0.0.1 -p 1080 --dashboard-bind 127.0.0.1 --dashboard-port 8081
```

Or build a binary:

```sh
go build -o sockshttpgate-proxy .
./sockshttpgate-proxy -h
```

Useful options include `-l` / `-p` for the listener, `-u` / `-P` for proxy authentication, `--no-udp`, `--upstream`, `--cert` / `--key`, `--dashboard-bind`, `--dashboard-port`, `--config`, `--allow`, and `--deny`. Run `-h` for the authoritative options and defaults.

## Test

```sh
go test ./...
go vet ./...
go build ./...
```

## Security

The proxy listener defaults to all interfaces. Bind it to localhost for local testing or configure authentication and network restrictions before exposing it. Keep the dashboard bound to localhost unless it is protected by a trusted authenticated reverse proxy. Do not commit config files containing credentials or usage data.
