# MediaDrop

Zero-dependency Node 18+ app. Run: `node lib/mediadrop.mjs` → http://localhost:3000. Change the name in `public/app.js` (`BRAND`) and `<title>`.

## Config (env vars)

- `LINK_SECRET` – signs expiring download links (set a fixed value in production; random per boot otherwise)
- `META_OEMBED_TOKEN` – Meta app token with oEmbed Read; required for Facebook/Instagram analysis (needs Meta app review)
- `ALLOW_DIRECT_FILES` (default true), `MAX_BYTES` (default 500 MB), `PORT`, `TRUST_PROXY=1` behind a reverse proxy
- Serve behind HTTPS (Caddy, nginx, or your host).

## What works

Platform detection, SSRF-guarded fetching (https/443 only, DNS result checked at connect time, redirects re-checked, provider allowlist), oEmbed metadata (YouTube, Vimeo, X, TikTok, Reddit; Facebook/Instagram with token), direct download of original media files via HMAC-signed 10-minute links with size cap, rate limit (20 req/min/IP), security headers.

## Not included yet

FFmpeg audio conversion + background jobs, persistent rate limiting, Facebook/Instagram live testing, legal pages are templates needing legal review.
