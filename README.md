# Siper Web Audit

Siper is a small, dependency-free passive web security auditor. It checks HTTPS/TLS, response security headers, redirect behavior, and cookie attributes, then produces a prioritized report and a 0–100 configuration score.

Licensed under the MIT License so anyone can use, inspect, modify, and redistribute it.

## Safety boundaries

- Passive HTTP/TLS inspection only; no exploitation, fuzzing, brute force, or authentication attempts.
- Private, loopback, link-local, multicast, and reserved network destinations are blocked to reduce SSRF risk.
- DNS results are validated and the selected public address is pinned for each request.
- Redirects are revalidated and capped at five hops.
- Use only against systems you own or have permission to test.

## Run the web interface

Requires Node.js 20 or newer.

```bash
npm start
```

Open `http://127.0.0.1:3000`.

## Run with Docker

```bash
docker build -t siper-web-audit .
docker run --rm -p 3000:3000 siper-web-audit
```

The production server honors `HOST`, `PORT`, and `RATE_LIMIT_MAX`. It exposes `GET /health` for deployment health checks. Public deployments should also apply rate limiting and TLS at the reverse proxy.

## Run from the command line

```bash
npm run audit -- https://example.com
```

## Test

```bash
npm test
```

## Current scope

This v0.1 release evaluates HSTS, CSP, clickjacking protection, MIME sniffing protection, Referrer-Policy, Permissions-Policy, COOP, CORP, TLS certificate validity, redirects, and Secure/HttpOnly/SameSite cookie attributes. It is a configuration review, not a penetration test.

## Suggested next steps

- Export reports as JSON and Markdown.
- Add regression snapshots so teams can detect security-header drift in CI.
- Add framework-specific remediation examples for Next.js, Nginx, Apache, and Cloudflare.
- Publish the repository with a license and contribution guide.
