# Go DoH for Render

A small DNS-over-HTTPS (RFC 8484-style) forwarder for Android DoH clients.

## Deploy

1. In Render, create a Web Service from this repository and set the **Root Directory** to `DoH`, or use the included `render.yaml` with the appropriate root directory.
2. Deploy the service.
3. DoH endpoint: `https://YOUR-SERVICE.onrender.com/dns-query`
4. Health check: `https://YOUR-SERVICE.onrender.com/health`

## Environment variables

- `PORT`: set by Render automatically; defaults to `8080` locally.
- `UPSTREAM_DOH`: HTTPS DoH upstream. Default: `https://cloudflare-dns.com/dns-query`.
- `BLOCKLIST`: optional comma/newline/semicolon/space-separated domains. Built-in defaults remain enabled.
- `BLOCKLIST_URLS`: optional list of HTTPS URLs separated by commas, semicolons, spaces, or newlines. Supports plain domain-per-line lists, hosts files (for example `0.0.0.0 ads.example`), and common Adblock-style entries (for example `||ads.example^`). Only HTTPS URLs are accepted.
- `BLOCKLIST_REFRESH`: optional refresh interval, parsed as a Go duration. Default: `6h`; minimum: `1m`.

Example configuration:

```text
BLOCKLIST_URLS=https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
BLOCKLIST_REFRESH=6h
BLOCKLIST=custom-ad.example,tracker.example
```

The server downloads remote lists on startup and refreshes them periodically. Downloads are limited to 10 MiB per source and have a timeout. If every remote source fails, the server keeps the current blocklist instead of replacing it with an empty list. Check application logs for source loading and refresh status.

Domains matching a blocked domain or any of its subdomains receive an NXDOMAIN response. A domain list may contain false positives, so start with a moderate list and test apps you use.

## Android

Use an Android app that supports a custom DoH URL, such as a compatible configuration in Rethink DNS. Enter:
`https://YOUR-SERVICE.onrender.com/dns-query`

Android's built-in **Private DNS** setting expects DNS-over-TLS (DoT), not a DoH URL. This project does not provide DoT.

## Important limitations

- This is a starter implementation, not a full HaGeZi Pro++ replacement.
- Public lists are controlled by their maintainers and may change at any time.
- The service is public unless you add authentication/rate limiting. Anyone who knows the URL can use it, which can create unwanted traffic or abuse. Consider adding access control before public production use.
- Render Web Services expose HTTPS, not arbitrary public UDP/TCP port 53 or DoT port 853.
- DNS query names pass through this service and the configured upstream; avoid using it if you do not trust those providers.
