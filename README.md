# threatmap

Private, live-ish cyber threat globe with a cyberpunk HUD. Stdlib Python backend + one HTML page, no build step.

```sh
python3 server.py        # http://127.0.0.1:8787  (first run downloads ~5 MB geo DB into data/)
python3 server.py test   # self-check
```

## What is real vs simulated

| Real (keyless feeds, refreshed every 10 min) | Simulated |
|---|---|
| Top 500 attacking IPs + report volumes, 24h ([SANS ISC DShield](https://isc.sans.edu/api/)) | Event timing: daily volumes replayed as a stream |
| Most targeted ports + Infocon level (DShield) | 10 defended assets (LDN-01 ...) |
| Botnet C2 servers, online/offline (= takedown) ([abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/)) | Firewall: half the assets use the DShield blocklist (block on first hit), the rest auto-ban an IP after 3 attempts for 4 min |
| Known exploited vulnerabilities ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)) | |
| IP -> country ([DB-IP Lite](https://db-ip.com/db/lite.php), CC BY 4.0) | Position within a country (jittered centroid) |

## Next add-ons
- Keyed feeds: abuse.ch URLhaus/ThreatFox (free key), AlienVault OTX, Cloudflare Radar.
- Hosting: Cloudflare Pages + Worker cron + Cloudflare Access (only your email can log in).
- Own honeypot (Cowrie/T-Pot on a VPS) for real-time attacks with a real target.

IP geolocation by DB-IP (https://db-ip.com).
