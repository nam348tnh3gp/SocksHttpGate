# Universal Proxy Pro

![Proxy Icon](https://img.shields.io/badge/Version-3.5-blue) ![Python](https://img.shields.io/badge/Python-3.6%2B-brightgreen) ![License](https://img.shields.io/badge/License-MIT-yellow)

A versatile proxy server written in Python that supports both SOCKS5 and HTTP/HTTPS protocols on the same port. It provides secure tunneling, authentication, real-time logging, traffic statistics, and enhanced stability for reliable connections in various network environments.

## Features

- **Dual Protocol Support**: Handles SOCKS5 and HTTP/HTTPS (including CONNECT method) on a single listening port.
- **Authentication**: Optional username/password authentication for both protocols (Basic for HTTP, username/password for SOCKS5).
- **Real-Time Logging**: Color-coded logs for connections, authentications, errors, and uptime statistics (uptime, active/total connections, SOCKS5/HTTP counts, bytes sent/received).
- **Stability Enhancements**: 
  - Retry mechanisms for connections, sends, and receives (up to 5 attempts).
  - Timeout handling (20 seconds default).
  - Buffer size optimized for large data (64KB).
  - Automatic cleanup of inactive connections to prevent memory leaks.
- **HTTP Method Support**: Full coverage for common methods including CONNECT, GET, POST, DELETE, HEAD, OPTIONS, TRACE, PUT, and PATCH.
- **Connection Limits**: Caps at 3000 concurrent connections to prevent overload.
- **Force Mode**: Kills existing processes on the port for easy restarts.
- **Cross-Platform**: Runs smoothly on Termux (Android), Linux, Windows, etc.

## Requirements

- Python 3.6 or higher.
- No external dependencies – uses only standard libraries (socket, threading, etc.).
- For Termux users: Ensure `python` is installed via `pkg install python`.

## Installation

1. Clone or download the script:
   ```
   git clone https://github.com/nam348tnh3gp/SocksHttpGate.git
   cd SocksHttpGate
   ```

2. Make the script executable (optional):
   ```
   chmod +x server.py  # Rename the script to proxy.py if needed
   ```

## Usage

Run the script with optional arguments:

```
python server.py [-l LISTEN] [-p PORT] [-u USERNAME] [-P PASSWORD] [--force]
```

### Arguments

- `-l, --listen`: Listening IP address (default: "0.0.0.0" – all interfaces).
- `-p, --port`: Listening port (default: 2160).
- `-u, --username`: Username for authentication (optional).
- `-P, --password`: Password for authentication (optional). If set with username, auth is required.
- `--force`: Kill any process using the specified port before starting.

### Examples

- Run without authentication on default port:
  ```
  python server.py
  ```

- Run with authentication on port 8080:
  ```
  python server.py -p 8080 -u user -P pass123
  ```

- Force start and bind to localhost:
  ```
  python server.py -l 127.0.0.1 -p 1080 --force
  ```

Once running, the proxy will log startup info and real-time stats every 8 seconds, e.g.:
```
Proxy STARTED → 0.0.0.0:2160 (Auth: user:pass123)
Uptime 00:00:08 │ Active    2/10     │ S5: 1  HTTP: 1 │ ↑ 12.5KB ↓ 8.3KB
```

## Testing

- **SOCKS5**: Use `curl --socks5 username:password@host:port https://ifconfig.me`
- **HTTP/HTTPS**: Use `curl -x http://username:password@host:port https://ifconfig.me`
- Monitor logs for connections, auth failures, and traffic.

## Configuration

Customize constants in the script:
- `MAX_CONN`: Max concurrent connections (default: 3000).
- `TIMEOUT`: Socket timeout (default: 20s).
- `RETRY`: Retry attempts for connect/send/recv (default: 5).
- `BUFFER_SIZE`: Data buffer size (default: 65536 bytes).

## Security Notes

- Use strong passwords for authentication.
- Run on a secure network; expose only necessary ports.
- The script cleans up old connections every hour to avoid memory issues.

## Troubleshooting

- **Port in use**: Use `--force` to kill conflicting processes.
- **Auth failures**: Check logs for details (e.g., mismatched username/password).
- **No internet**: Ensure the host machine has network access.
- **Errors**: Increase logging level to DEBUG in `logging.basicConfig` for more info.

## License

MIT License – Free to use, modify, and distribute. See [LICENSE](LICENSE) for details.

## Credits

Developed with inspiration from open-source proxy tools. Contributions welcome! If you encounter issues, open a GitHub issue.
