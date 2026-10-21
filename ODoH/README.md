# SocksHttpGate ODoH — Termux local test harness

[![ODoH CI](https://img.shields.io/github/actions/workflow/status/nam348tnh3gp/SocksHttpGate/odoh.yml?branch=main&style=for-the-badge&label=ODoH%20CI)](https://github.com/nam348tnh3gp/SocksHttpGate/actions/workflows/odoh.yml)
[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![Protocol](https://img.shields.io/badge/Protocol-RFC%209230%20ODoH-6f42c1?style=for-the-badge)](https://www.rfc-editor.org/rfc/rfc9230)
[![Docker build](https://img.shields.io/badge/Docker-Proxy%20%2B%20Target-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://github.com/nam348tnh3gp/SocksHttpGate/actions/workflows/odoh.yml)
[![Tests](https://img.shields.io/badge/Tests-Race%20%2B%20Fuzzing-success?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate/actions/workflows/odoh.yml)
[![Status](https://img.shields.io/badge/Status-Experimental-orange?style=for-the-badge)](#important-security-warning)
[![Security](https://img.shields.io/badge/NOT%20FOR%20PRODUCTION-Archived%20reference-critical?style=for-the-badge)](#important-security-warning)
[![Last commit](https://img.shields.io/github/last-commit/nam348tnh3gp/SocksHttpGate/main/ODoH?style=for-the-badge)](https://github.com/nam348tnh3gp/SocksHttpGate/commits/main/ODoH)
[![License](https://img.shields.io/github/license/nam348tnh3gp/SocksHttpGate?style=for-the-badge)](../LICENSE)

This is a **local interoperability smoke-test harness**, not a production-ready ODoH service.

It downloads and builds the archived Cloudflare Go reference server and client, creates a short-lived self-signed certificate, and tries an ODoH DNS query through a local proxy/target pair.

## Termux prerequisites

```sh
pkg update
pkg install git golang openssl curl
```

## Run

Because this uses an archived, legacy reference server, explicitly acknowledge the risk before launching:

```sh
chmod +x run.sh
ALLOW_LEGACY_REFERENCE=YES ./run.sh
```

Optional test parameters:

```sh
ALLOW_LEGACY_REFERENCE=YES DOMAIN=cloudflare.com TYPE=AAAA PORT=4567 ./run.sh
```

The first run downloads Go source and dependencies and may take several minutes.

## Important security warning

- The reference implementation is archived/legacy and has had a publicly reported SSRF concern. This harness is intended for local experimentation only.
- Do not deploy this server to Render, a VPS, or any public interface.
- The script's source scan for loopback references is only a weak sanity check. It **does not prove** that the listener binds only to loopback. Inspect the upstream listener implementation before running; if you cannot verify the bind address, do not run it on an untrusted network.
- The harness cannot meet the threat model requiring protection against a malicious host administrator. A normal Termux process and a self-signed localhost certificate do not provide TEE/remote-attestation guarantees.
- This smoke test does not prove RFC 9230 conformance, resistance to traffic correlation, or production security.
- `curl -k` is used only for a local readiness probe; it is not used to process the DNS request. The ODoH client uses the local certificate as its trust bundle.
- Do not put real/sensitive DNS traffic through this test setup.

## What a successful test means

A successful client response indicates that the reference client/server were able to complete a basic ODoH query in this local environment. It does not mean that the server is safe to expose publicly.

## Next production steps

For a production deployment, use a maintained and audited RFC 9230 implementation, enforce a fixed/allowlisted Target to prevent SSRF, isolate Proxy and Target under different trust domains, keep the Target private key out of the Proxy environment, disable query logging, and test with published RFC test vectors.
