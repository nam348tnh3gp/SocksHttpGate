# Go DoH for Render

A small DNS-over-HTTPS (RFC 8484-style) forwarder for Android DoH clients.

## Deploy

1. Upload these files to a GitHub repository.
2. In Render, create a Web Service from the repository and choose Docker, or use the included `render.yaml`.
3. After deployment, your endpoint is:
   `https://YOUR-SERVICE.onrender.com/dns-query`
4. Health check:
   `https://YOUR-SERVICE.onrender.com/health`

## Render environment variables

- `PORT`: set by Render automatically.
- `UPSTREAM_DOH`: HTTPS DoH upstream. Default: `https://cloudflare-dns.com/dns-query`.
- `BLOCKLIST`: optional comma/newline/semicolon/space-separated domains. Matching domain and its subdomains return NXDOMAIN.

Example:
`doubleclick.net,googlesyndication.com,googleadservices.com,adnxs.net`

## Android

Use an Android app that supports a custom DoH URL, such as a compatible configuration in Rethink DNS. Enter:
`https://YOUR-SERVICE.onrender.com/dns-query`

Android's built-in **Private DNS** setting expects DNS-over-TLS (DoT), not a DoH URL. This project does not provide DoT.

## Important limitations

- This is a starter implementation, not a full HaGeZi Pro++ replacement.
- The included list is only a small example; it does not download or synchronize HaGeZi lists.
- The service is public unless you add authentication/rate limiting. Anyone who knows the URL can use it, which can create unwanted traffic or abuse. Consider adding access control before public production use.
- Render Web Services expose HTTPS, not arbitrary public UDP/TCP port 53 or DoT port 853.
- DNS query names pass through this service and the configured upstream; avoid using it if you do not trust those providers.
