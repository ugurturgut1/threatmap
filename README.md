# threatmap

Live cyber threat globe with a cyberpunk HUD. One stdlib Python script builds `web/data/state.json`; one static HTML page renders it. No build step, no dependencies.

```sh
python3 build.py serve   # local: pulls every 10 min, http://127.0.0.1:8787
python3 build.py         # one pull (what GitHub Actions runs hourly)
python3 build.py test    # self-check
```

Keys live in `.env` (gitignored) locally and in repo secrets on GitHub:
`RADAR_TOKEN`, `ABUSECH_KEY`, `ABUSEIPDB_KEY`, `OTX_KEY`, optional `NTFY_TOPIC`. Any missing key just switches that feed off.

```sh
gh secret set -f ~/threatmap/.env --repo ugurturgut1/threatmap   # copy .env into repo secrets
gh workflow run build-and-deploy --repo ugurturgut1/threatmap    # deploy now instead of waiting for the hour
```

## Data: real vs simulated

| Feed | What it drives | Free tier / budget used |
|---|---|---|
| [SANS ISC DShield](https://isc.sans.edu/api/) | top 500 attacking IPs, targeted ports, Infocon | keyless |
| [abuse.ch Feodo](https://feodotracker.abuse.ch/) | botnet C2s, online/offline = takedown alerts | keyless |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | exploited-vuln ticker + new-KEV alerts | keyless |
| [Cloudflare Radar](https://radar.cloudflare.com/) | real L7/L3 attack origin→target arcs, mitigation mix, DDoS vectors | free API, CC BY-NC 4.0 |
| [abuse.ch URLhaus + ThreatFox](https://abuse.ch/) | malware URLs + C2 IOCs on the globe and timeline | free Auth-Key, fair use |
| [LevelBlue OTX](https://otx.alienvault.com/) | campaigns, adversaries, ATT&CK techniques in the wild | free account |
| [AbuseIPDB](https://www.abuseipdb.com/) | abuse scores, ISP drill-down, reports on the timeline | free: blacklist 2×/day per host (limit 5), ≤400 checks/day (limit 1000) |
| [DB-IP Lite](https://db-ip.com) | IP → country (CC BY 4.0) | free download |

**Simulated** (labelled SIM in the UI): live event timing (replayed from the real distributions), the 10 defended assets and their firewall (ban threshold / ban length / blocklist toggles are live controls).
**Real timeline**: the 24h replay is built from changes between pulls (takedowns, new C2s, new KEVs, new top scanners, new OTX/URLhaus/ThreatFox entries, AbuseIPDB reports).

## Features
Live + 24h replay with a clickable timeline · filters by feed group and country · click any point or event for drill-down (ISP, abuse score, Tor, firewall state, links to ISC/AbuseIPDB/OTX/Feodo) · defence controls · MITRE ATT&CK (OTX in-the-wild + port→technique for the sim) · alerts (in-page, browser notifications, optional phone push via [ntfy](https://ntfy.sh): install the app, subscribe to a long random topic name, save it as the `NTFY_TOPIC` secret) · sound (SFX button) · mobile layout · boot sequence.

## Hosting
GitHub Actions rebuilds hourly and deploys to GitHub Pages. History persists between runs in the Actions cache (no data commits).
A Pages site is public on every personal plan (private Pages needs GitHub Enterprise Cloud); the page is `noindex`. Pages from a private repo needs GitHub Pro (free with the Student Developer Pack).
