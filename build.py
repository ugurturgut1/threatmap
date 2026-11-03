#!/usr/bin/env python3
"""threatmap data builder: pulls threat feeds, geolocates offline, keeps 24h history, writes web/data/state.json.

  python3 build.py          one pull (what GitHub Actions runs every 30 min)
  python3 build.py serve    pull every 10 min + serve web/ on http://127.0.0.1:8787
  python3 build.py test     self-check

Keys come from the environment or the nearest .env: RADAR_TOKEN ABUSECH_KEY ABUSEIPDB_KEY OTX_KEY, optional NTFY_TOPIC.
Every keyed source is optional and stays inside its free tier (budgets below). Stdlib only.
"""
import bisect, csv, functools, gzip, http.server, ipaddress, json, os, sys, threading, time, urllib.error, urllib.request
from datetime import date, datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(ROOT, "cache")  # persisted between Actions runs via actions/cache
OUT = os.path.join(ROOT, "web", "data")
UA = "threatmap/0.2 (personal research dashboard)"
DAY = 86400
# Free-tier budgets. AbuseIPDB free = 5 blacklist + 1000 check calls/day, shared by every place this runs.
BLACKLIST_EVERY = 12 * 3600    # 2/day here; Actions + a local serve together stay <= 5/day
CHECKS_PER_DAY = 400           # leaves room for a local `serve` and Actions at the same time
CHECKS_PER_RUN = 12
HISTORY_CAP = 3000
GEOJSON = "https://raw.githubusercontent.com/vasturiano/globe.gl/master/example/datasets/ne_110m_admin_0_countries.geojson"
EXTRA_CENTROIDS = {"SG": (1.35, 103.82), "HK": (22.32, 114.17), "MT": (35.9, 14.4), "LU": (49.8, 6.1),
                   "BH": (26.0, 50.55), "MU": (-20.2, 57.5), "MO": (22.2, 113.55), "AD": (42.5, 1.5),
                   "MC": (43.73, 7.42), "LI": (47.16, 9.55), "SC": (-4.68, 55.49), "BB": (13.19, -59.54)}
NAME_ALIASES = {"United States": "US", "USA": "US", "Russian Federation": "RU", "Korea, Republic of": "KR",
                "Republic of Korea": "KR", "Iran, Islamic Republic of": "IR", "Viet Nam": "VN", "Czech Republic": "CZ",
                "Hong Kong": "HK", "Singapore": "SG", "Taiwan, Province of China": "TW", "UK": "GB", "Türkiye": "TR"}


def load_env():
    d = ROOT
    for _ in range(4):
        p = os.path.join(d, ".env")
        if os.path.isfile(p):
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip().strip("\"'"))
            return
        d = os.path.dirname(d)


def fetch(url, headers=None, data=None, timeout=60):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, "Accept": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def getj(url, headers=None, data=None):
    return json.loads(fetch(url, headers, data))


def cached(name, url, max_age):
    path = os.path.join(CACHE, name)
    if not os.path.exists(path) or time.time() - os.path.getmtime(path) > max_age:
        os.makedirs(CACHE, exist_ok=True)
        blob = fetch(url, timeout=300)
        with open(path + ".tmp", "wb") as f:
            f.write(blob)
        os.replace(path + ".tmp", path)
    return path


def read_json(name, default):
    try:
        with open(os.path.join(CACHE, name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".tmp", "w") as f:
        json.dump(obj, f, separators=(",", ":"))
    os.replace(path + ".tmp", path)


def parse_ts(s):
    """abuse.ch '2026-11-03 14:00:00 UTC', ISO with or without offset -> epoch seconds."""
    s = s.replace(" UTC", "").replace("Z", "+00:00").replace(" ", "T")
    dt = datetime.fromisoformat(s)
    return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp())


# ---------------------------------------------------------------- geo
class Geo:
    def __init__(self, rows, centroids, names=None):
        rows.sort()
        self.starts = [r[0] for r in rows]
        self.rows = rows
        self.centroids = centroids
        self.names = names or {}

    def country(self, ip):
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        i = bisect.bisect_right(self.starts, n) - 1
        return self.rows[i][2] if i >= 0 and self.rows[i][0] <= n <= self.rows[i][1] else None

    def locate(self, ip, cc=None):
        cc = cc or self.country(ip)
        if cc not in self.centroids:
            return cc, None, None
        lat, lng = self.centroids[cc]
        h = int(ipaddress.IPv4Address(ip)) * 2654435761 % 2**32  # stable spread inside the country
        return cc, round(lat + ((h & 0xFFFF) / 0xFFFF - 0.5) * 6, 3), round(lng + ((h >> 16) / 0xFFFF - 0.5) * 8, 3)

    def cc_for_name(self, name):
        return NAME_ALIASES.get(name) or self.names.get(name.lower())


def centroids_from_geojson(gj):
    out, names = {}, {}
    for feat in gj["features"]:
        p = feat["properties"]
        cc = p.get("ISO_A2") if p.get("ISO_A2") not in (None, "-99") else p.get("ISO_A2_EH")
        if not cc or cc == "-99":
            continue
        g = feat["geometry"]
        polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
        ring = max((poly[0] for poly in polys), key=len)
        out[cc] = (round(sum(pt[1] for pt in ring) / len(ring), 2), round(sum(pt[0] for pt in ring) / len(ring), 2))
        for k in ("NAME", "NAME_LONG", "ADMIN", "FORMAL_EN"):
            if p.get(k):
                names[p[k].lower()] = cc
    return out, names


def load_geo():
    today = date.today()
    prev = (today.year - (today.month == 1), (today.month - 2) % 12 + 1)
    path = None
    for y, m in ((today.year, today.month), prev):  # DB-IP publishes monthly
        try:
            path = cached("dbip-country.csv.gz", f"https://download.db-ip.com/free/dbip-country-lite-{y}-{m:02d}.csv.gz", 35 * DAY)
            break
        except Exception as e:
            print("db-ip download failed:", e)
    rows = []
    with gzip.open(path, "rt") as f:
        for a, b, cc in csv.reader(f):
            if ":" not in a:
                rows.append((int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b)), cc))
    with open(cached("countries.geojson", GEOJSON, 365 * DAY)) as f:
        cents, names = centroids_from_geojson(json.load(f))
    return Geo(rows, {**EXTRA_CENTROIDS, **cents}, names)


# ---------------------------------------------------------------- sources (each returns a dict or raises)
def src_dshield(geo):
    attackers = []
    for r in getj("https://isc.sans.edu/api/topips/records/500?json"):
        cc, lat, lng = geo.locate(r["source"])
        if lat is not None:
            attackers.append({"ip": r["source"], "cc": cc, "lat": lat, "lng": lng, "reports": r["reports"], "targets": r["targets"]})
    ports = [{"port": v["targetport"], "records": v["records"], "sources": v["sources"]}
             for k, v in getj("https://isc.sans.edu/api/topports/records/25?json").items() if k.isdigit()]
    return {"attackers": attackers, "ports": ports, "infocon": getj("https://isc.sans.edu/api/infocon?json").get("status", "unknown")}


def src_feodo(geo):
    out = []
    for r in getj("https://feodotracker.abuse.ch/downloads/ipblocklist.json"):
        cc, lat, lng = geo.locate(r["ip_address"])
        if lat is not None:
            out.append({"ip": r["ip_address"], "port": r["port"], "cc": r.get("country") or cc, "lat": lat, "lng": lng,
                        "status": r["status"], "malware": r["malware"], "as": r.get("as_name"), "last_online": r.get("last_online")})
    return {"c2": out}


def src_kev():
    d = getj("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    vulns = sorted(d["vulnerabilities"], key=lambda v: v["dateAdded"], reverse=True)[:25]
    keep = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "knownRansomwareCampaignUse")
    return {"kev": [{k: v.get(k) for k in keep} for v in vulns], "kev_total": d["count"]}


def src_radar():
    tok = os.environ.get("RADAR_TOKEN")
    if not tok:
        return None
    h = {"Authorization": f"Bearer {tok}"}
    base = "https://api.cloudflare.com/client/v4/radar/attacks"

    def res(path):
        r = getj(f"{base}/{path}{'&' if '?' in path else '?'}dateRange=1d&format=json", h)["result"]
        return r[[k for k in r if k != "meta"][0]]

    pairs = lambda rows: [{"o": r["originCountryAlpha2"], "t": r["targetCountryAlpha2"], "v": float(r["value"])} for r in rows]
    return {"l7": pairs(res("layer7/top/attacks?limit=100")), "l3": pairs(res("layer3/top/attacks?limit=100")),
            "mitigation": {k: float(v) for k, v in res("layer7/summary/mitigation_product").items()},
            "vectors": {k: float(v) for k, v in res("layer3/summary/vector").items()},
            "protocols": {k: float(v) for k, v in res("layer3/summary/protocol").items()}}


def src_abusech(geo):
    key = os.environ.get("ABUSECH_KEY")
    if not key:
        return None
    h = {"Auth-Key": key}
    urls = []
    for u in getj("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/500/", h).get("urls") or []:
        cc, lat, lng = geo.locate(u.get("host", ""))
        if lat is not None:  # only IP-hosted URLs have a location without DNS lookups
            urls.append({"id": u["id"], "t": parse_ts(u["date_added"]), "ip": u["host"], "cc": cc, "lat": lat, "lng": lng,
                         "threat": u.get("threat"), "status": u.get("url_status"), "tags": (u.get("tags") or [])[:4]})
    iocs = []
    tf = getj("https://threatfox-api.abuse.ch/api/v1/", {**h, "Content-Type": "application/json"}, json.dumps({"query": "get_iocs", "days": 1}).encode())
    for i in tf.get("data") or []:
        if i.get("ioc_type") != "ip:port":
            continue
        ip, _, port = i["ioc"].rpartition(":")
        cc, lat, lng = geo.locate(ip)
        if lat is not None:
            iocs.append({"id": i["id"], "t": parse_ts(i["first_seen"]), "ip": ip, "port": port, "cc": cc, "lat": lat, "lng": lng,
                         "malware": i.get("malware_printable"), "type": i.get("threat_type"), "conf": i.get("confidence_level")})
    return {"urlhaus": urls, "threatfox": iocs}


def src_abuseipdb(geo, attackers, now):
    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        return None
    h = {"Key": key}
    bl = read_json("abuseipdb_blacklist.json", {"at": 0, "data": []})
    fresh_pull = now - bl["at"] >= BLACKLIST_EVERY
    if fresh_pull:
        bl = {"at": now, "data": getj("https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=10000", h)["data"]}
        write_json(os.path.join(CACHE, "abuseipdb_blacklist.json"), bl)
    scores = {r["ipAddress"]: r["abuseConfidenceScore"] for r in bl["data"]}

    checks = read_json("abuseipdb_checks.json", {})  # ip -> details, refreshed every 3 days
    budget = read_json("abuseipdb_budget.json", {"day": "", "used": 0})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if budget["day"] != today:
        budget = {"day": today, "used": 0}
    todo = [a["ip"] for a in sorted(attackers, key=lambda a: -a["reports"]) if now - checks.get(a["ip"], {}).get("at", 0) > 3 * DAY]
    for ip in todo[:max(0, min(CHECKS_PER_RUN, CHECKS_PER_DAY - budget["used"]))]:
        d = getj(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=30", h)["data"]
        budget["used"] += 1
        checks[ip] = {"at": now, "score": d["abuseConfidenceScore"], "isp": d.get("isp"), "usage": d.get("usageType"),
                      "domain": d.get("domain"), "tor": d.get("isTor"), "reports": d.get("totalReports"),
                      "users": d.get("numDistinctUsers"), "last": d.get("lastReportedAt")}
    checks = {ip: c for ip, c in checks.items() if now - c["at"] < 7 * DAY}
    write_json(os.path.join(CACHE, "abuseipdb_checks.json"), checks)
    write_json(os.path.join(CACHE, "abuseipdb_budget.json"), budget)

    reports = []
    if fresh_pull:  # newest blacklist reports become timeline events
        for r in sorted(bl["data"], key=lambda r: r["lastReportedAt"], reverse=True)[:400]:
            cc, lat, lng = geo.locate(r["ipAddress"], r.get("countryCode"))
            if lat is not None:
                reports.append({"t": parse_ts(r["lastReportedAt"]), "ip": r["ipAddress"], "cc": cc, "lat": lat, "lng": lng, "score": r["abuseConfidenceScore"]})
    return {"scores": scores, "checks": checks, "reports": reports, "blacklist_size": len(scores), "budget_used": budget["used"]}


def src_otx(geo, now):
    key = os.environ.get("OTX_KEY")
    if not key:
        return None
    since = datetime.fromtimestamp(now - 3 * DAY, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    d = getj(f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit=40&modified_since={since}", {"X-OTX-API-KEY": key})
    out = []
    for p in d.get("results", []):
        ids = [a["id"] if isinstance(a, dict) else a for a in p.get("attack_ids") or []]
        fams = [f["display_name"] if isinstance(f, dict) else f for f in p.get("malware_families") or []]
        targets = [cc for cc in (geo.cc_for_name(n) for n in p.get("targeted_countries") or []) if cc]
        out.append({"id": p["id"], "t": parse_ts(p["created"]), "name": p["name"], "adversary": p.get("adversary") or None,
                    "malware": fams[:6], "targets": targets, "attack": ids[:30], "industries": (p.get("industries") or [])[:5],
                    "tags": (p.get("tags") or [])[:6]})
    return {"pulses": out}


# ---------------------------------------------------------------- history + alerts
def update_history(hist, cur, now):
    """Turn changes between runs into timeline events + alerts. Pure: returns (hist, new_alerts)."""
    seen, ev, alerts = hist.setdefault("seen", {}), hist.setdefault("events", []), []
    first = not seen
    push = lambda e: ev.append(e)

    prev_c2 = seen.get("c2", {})
    for c in cur.get("c2", []):
        was = prev_c2.get(c["ip"])
        if was == "online" and c["status"] != "online":
            push({"t": now, "k": "TAKEDOWN", "ip": c["ip"], "cc": c["cc"], "lat": c["lat"], "lng": c["lng"], "x": f"{c['malware']} C2 went offline"})
            alerts.append(f"Takedown: {c['malware']} C2 {c['ip']} went offline")
        elif c["status"] == "online" and was != "online" and not first:
            push({"t": now, "k": "C2", "ip": c["ip"], "cc": c["cc"], "lat": c["lat"], "lng": c["lng"], "x": f"{c['malware']} C2 came online"})
            alerts.append(f"New {c['malware']} C2 online: {c['ip']}:{c['port']} ({c['cc']})")
    if "c2" in cur:
        seen["c2"] = {c["ip"]: c["status"] for c in cur["c2"]}

    if "kev" in cur:
        known = set(seen.get("kev", []))
        for v in cur["kev"]:
            if v["cveID"] not in known and not first:
                push({"t": now, "k": "KEV", "x": f"{v['cveID']} {v['vendorProject']} {v['product']}"})
                alerts.append(f"New exploited vuln (CISA KEV): {v['cveID']} {v['vendorProject']} {v['product']}")
        seen["kev"] = sorted(known | {v["cveID"] for v in cur["kev"]})[-200:]

    if "infocon" in cur:
        if seen.get("infocon") not in (None, cur["infocon"]):
            alerts.append(f"SANS Infocon changed {seen['infocon']} -> {cur['infocon']}")
        seen["infocon"] = cur["infocon"]

    if "attackers" in cur:
        prev = set(seen.get("attackers", []))
        if prev:
            for a in [a for a in cur["attackers"] if a["ip"] not in prev][:150]:
                push({"t": now, "k": "SCAN", "ip": a["ip"], "cc": a["cc"], "lat": a["lat"], "lng": a["lng"], "x": f"new top-500 scanner ({a['reports']} reports)"})
        seen["attackers"] = [a["ip"] for a in cur["attackers"]]

    def once(kind, items, label):
        ids = set(seen.get(kind, []))
        for it in items:
            if it["id"] not in ids:
                push({"t": it["t"], **label(it)})
        seen[kind] = [it["id"] for it in items][-1000:]

    once("otx", cur.get("pulses", []), lambda p: {"k": "CAMPAIGN", "tg": p["targets"], "x": (f"[{p['adversary']}] " if p["adversary"] else "") + p["name"]})
    once("urlhaus", cur.get("urlhaus", []), lambda u: {"k": "MALWARE", "ip": u["ip"], "cc": u["cc"], "lat": u["lat"], "lng": u["lng"], "x": f"{u['threat'] or 'malware'} URL {' '.join(u['tags'])}"})
    once("threatfox", cur.get("threatfox", []), lambda i: {"k": "IOC", "ip": i["ip"], "cc": i["cc"], "lat": i["lat"], "lng": i["lng"], "x": f"{i['malware']} {i['type']} :{i['port']}"})
    for r in cur.get("reports", []):
        push({"t": r["t"], "k": "REPORTED", "ip": r["ip"], "cc": r["cc"], "lat": r["lat"], "lng": r["lng"], "x": f"AbuseIPDB score {r['score']}"})

    cut = now - DAY
    ev[:] = sorted((e for e in ev if cut <= e["t"] <= now + 3600), key=lambda e: e["t"])[-HISTORY_CAP:]
    hist["alerts"] = (hist.get("alerts", []) + [{"t": now, "x": a} for a in alerts])[-50:]
    return hist, alerts


def notify(alerts):
    topic = os.environ.get("NTFY_TOPIC")
    for a in alerts[:5] if topic else []:
        try:
            fetch(f"https://ntfy.sh/{topic}", {"Title": "threatmap", "Tags": "rotating_light"}, a.encode())
        except Exception as e:
            print("ntfy failed:", e)


# ---------------------------------------------------------------- run
def run(geo):
    now = int(time.time())
    last = read_json("last.json", {})  # last good result per source, so one failing feed never blanks the map
    sources, cur = {}, {}

    def pull(name, fn):
        try:
            res = fn()
            if res is None:
                sources[name] = {"ok": None, "err": "no key"}
                return
            last[name] = {"at": now, "data": res}
            sources[name] = {"ok": True, "at": now}
        except Exception as e:
            msg = f"HTTP {e.code}" if isinstance(e, urllib.error.HTTPError) else f"{type(e).__name__}: {e}"
            sources[name] = {"ok": False, "err": msg[:120], "at": last.get(name, {}).get("at")}
            print(f"{name} failed: {msg}")
        if name in last and sources[name]["ok"] is not None:
            cur.update(last[name]["data"])

    pull("dshield", lambda: src_dshield(geo))
    pull("feodo", lambda: src_feodo(geo))
    pull("kev", src_kev)
    pull("radar", src_radar)
    pull("abusech", lambda: src_abusech(geo))
    pull("otx", lambda: src_otx(geo, now))
    pull("abuseipdb", lambda: src_abuseipdb(geo, cur.get("attackers", []), now))
    if not sources["abuseipdb"]["ok"]:  # stale reports were already added to history on the run that pulled them
        cur.pop("reports", None)

    hist, alerts = update_history(read_json("history.json", {}), cur, now)
    write_json(os.path.join(CACHE, "history.json"), hist)
    write_json(os.path.join(CACHE, "last.json"), {k: v for k, v in last.items()})
    notify(alerts)

    scores, checks = cur.get("scores", {}), cur.get("checks", {})
    for a in cur.get("attackers", []):
        if a["ip"] in scores:
            a["abuse"] = scores[a["ip"]]
        if a["ip"] in checks:
            a["info"] = {k: v for k, v in checks[a["ip"]].items() if k != "at"}
    state = {"updated": now, "sources": sources, "infocon": cur.get("infocon", "unknown"),
             "attackers": cur.get("attackers", []), "ports": cur.get("ports", []), "c2": cur.get("c2", []),
             "kev": cur.get("kev", []), "kev_total": cur.get("kev_total", 0),
             "radar": {k: cur[k] for k in ("l7", "l3", "mitigation", "vectors", "protocols") if k in cur},
             "pulses": cur.get("pulses", []), "threatfox": cur.get("threatfox", [])[-300:], "urlhaus": cur.get("urlhaus", [])[-300:],
             "abuseipdb": {"blacklist_size": cur.get("blacklist_size", 0)},
             "events": hist["events"], "alerts": hist["alerts"],
             "centroids": {cc: list(v) for cc, v in geo.centroids.items()}}
    write_json(os.path.join(OUT, "state.json"), state)
    ok = sum(1 for s in sources.values() if s["ok"])
    print(time.strftime("%H:%M:%S"), f"built: {ok}/{len(sources)} sources ok, {len(state['attackers'])} attackers, "
          f"{len(hist['events'])} timeline events, {len(alerts)} new alerts")


def serve():
    geo = load_geo()

    def loop():
        while True:
            try:
                run(geo)
            except Exception as e:  # keep serving the last state.json
                print("run failed:", e)
            time.sleep(600)

    threading.Thread(target=loop, daemon=True).start()
    port = int(os.environ.get("PORT", 8787))
    print(f"threatmap on http://127.0.0.1:{port}")
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):
            pass

    handler = functools.partial(Quiet, directory=os.path.join(ROOT, "web"))
    http.server.ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()


def selftest():
    geo = Geo([(16777216, 16777471, "AU"), (167772160, 184549375, "XX")], {"AU": (-25.0, 134.0)}, {"australia": "AU"})
    assert geo.country("1.0.0.7") == "AU" and geo.country("1.0.1.0") is None and geo.country("nope") is None
    cc, lat, lng = geo.locate("1.0.0.7")
    assert cc == "AU" and abs(lat + 25) <= 3 and abs(lng - 134) <= 4
    assert geo.locate("10.0.0.1") == ("XX", None, None)
    assert geo.locate("10.0.0.1", "AU")[0] == "AU"  # caller-supplied country wins
    assert geo.cc_for_name("Australia") == "AU" and geo.cc_for_name("United States") == "US"
    sq = {"type": "Feature", "properties": {"ISO_A2": "-99", "ISO_A2_EH": "FR", "NAME": "France"},
          "geometry": {"type": "Polygon", "coordinates": [[[0, 40], [10, 40], [10, 50], [0, 50]]]}}
    assert centroids_from_geojson({"features": [sq]}) == ({"FR": (45.0, 5.0)}, {"france": "FR"})
    assert parse_ts("2026-11-03 14:00:00 UTC") == parse_ts("2026-11-03T14:00:00+00:00") == parse_ts("2026-11-03T14:00:00")

    c2 = lambda status: {"ip": "1.0.0.9", "port": 443, "cc": "AU", "lat": 1, "lng": 2, "status": status, "malware": "Emotet"}
    kev = lambda *ids: [{"cveID": i, "vendorProject": "v", "product": "p"} for i in ids]
    att = lambda *ips: [{"ip": ip, "cc": "AU", "lat": 1, "lng": 2, "reports": 5} for ip in ips]
    t0 = 1_800_000_000
    h, al = update_history({}, {"c2": [c2("online")], "kev": kev("A"), "infocon": "green", "attackers": att("1.1.1.1")}, t0)
    assert al == [] and h["events"] == []  # first run only records a baseline
    h, al = update_history(h, {"c2": [c2("offline")], "kev": kev("A", "B"), "infocon": "yellow", "attackers": att("1.1.1.1", "2.2.2.2"),
                               "pulses": [{"id": "p1", "t": t0 + 5, "name": "Op X", "adversary": "APT0", "targets": ["AU"]}]}, t0 + 10)
    kinds = sorted(e["k"] for e in h["events"])
    assert kinds == ["CAMPAIGN", "KEV", "SCAN", "TAKEDOWN"], kinds
    assert len(al) == 3 and any("Infocon" in a for a in al) and any("Takedown" in a for a in al)
    h, al = update_history(h, {"pulses": [{"id": "p1", "t": t0 + 5, "name": "Op X", "adversary": None, "targets": []}]}, t0 + 20)
    assert sum(e["k"] == "CAMPAIGN" for e in h["events"]) == 1  # same pulse is not re-added
    h, _ = update_history(h, {}, t0 + 2 * DAY)
    assert h["events"] == []  # older than 24h is pruned
    print("selftest ok")


if __name__ == "__main__":
    load_env()
    if sys.argv[1:] == ["test"]:
        selftest()
    elif sys.argv[1:] == ["serve"]:
        serve()
    else:
        run(load_geo())
