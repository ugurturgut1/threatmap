#!/usr/bin/env python3
"""threatmap backend: polls keyless threat feeds, geolocates IPs offline, serves the UI.

Run:  python3 server.py            -> http://127.0.0.1:8787
Test: python3 server.py test
Stdlib only.
"""
import bisect, csv, gzip, http.server, ipaddress, json, os, sys, threading, time, urllib.request
from datetime import date

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
UA = "threatmap/0.1 (personal research dashboard)"
REFRESH = 600  # seconds; DShield asks for polite polling
FEEDS = {
    "attackers": "https://isc.sans.edu/api/topips/records/500?json",
    "ports": "https://isc.sans.edu/api/topports/records/25?json",
    "infocon": "https://isc.sans.edu/api/infocon?json",
    "c2": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}
GEOJSON = "https://raw.githubusercontent.com/vasturiano/globe.gl/master/example/datasets/ne_110m_admin_0_countries.geojson"
# Countries too small for the 110m map.
EXTRA_CENTROIDS = {"SG": (1.35, 103.82), "HK": (22.32, 114.17), "MT": (35.9, 14.4), "LU": (49.8, 6.1),
                   "BH": (26.0, 50.55), "MU": (-20.2, 57.5), "MO": (22.2, 113.55), "AD": (42.5, 1.5),
                   "MC": (43.73, 7.42), "LI": (47.16, 9.55), "SC": (-4.68, 55.49), "BB": (13.19, -59.54)}


def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def cached(name, url, max_age):
    """Download url to data/name unless a fresh copy exists."""
    path = os.path.join(DATA, name)
    if not os.path.exists(path) or time.time() - os.path.getmtime(path) > max_age:
        os.makedirs(DATA, exist_ok=True)
        blob = fetch(url, timeout=300)
        with open(path + ".tmp", "wb") as f:
            f.write(blob)
        os.replace(path + ".tmp", path)
    return path


class Geo:
    def __init__(self, rows, centroids):
        rows.sort()
        self.starts = [r[0] for r in rows]
        self.rows = rows
        self.centroids = centroids

    def country(self, ip):
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        i = bisect.bisect_right(self.starts, n) - 1
        if i >= 0 and self.rows[i][0] <= n <= self.rows[i][1]:
            return self.rows[i][2]
        return None

    def locate(self, ip):
        cc = self.country(ip)
        if cc not in self.centroids:
            return cc, None, None
        lat, lng = self.centroids[cc]
        # Deterministic spread so IPs from one country don't stack on one pixel.
        h = int(ipaddress.IPv4Address(ip)) * 2654435761 % 2**32
        return cc, lat + ((h & 0xFFFF) / 0xFFFF - 0.5) * 6, lng + ((h >> 16) / 0xFFFF - 0.5) * 8


def load_geo():
    # DB-IP publishes monthly; fall back to last month early in the month.
    today = date.today()
    prev = (today.year - (today.month == 1), (today.month - 2) % 12 + 1)
    path = None
    for y, m in ((today.year, today.month), prev):
        try:
            path = cached("dbip-country.csv.gz", f"https://download.db-ip.com/free/dbip-country-lite-{y}-{m:02d}.csv.gz", 35 * 86400)
            break
        except Exception as e:
            print("db-ip download failed:", e)
    rows = []
    with gzip.open(path, "rt") as f:
        for a, b, cc in csv.reader(f):
            if ":" not in a:
                rows.append((int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b)), cc))
    with open(cached("countries.geojson", GEOJSON, 365 * 86400)) as f:
        countries = json.load(f)
    return Geo(rows, {**EXTRA_CENTROIDS, **centroids_from_geojson(countries)})


def centroids_from_geojson(gj):
    """Mean vertex of each country's largest polygon ring (good enough for a globe)."""
    out = {}
    for feat in gj["features"]:
        p = feat["properties"]
        cc = p.get("ISO_A2") if p.get("ISO_A2") not in (None, "-99") else p.get("ISO_A2_EH")
        if not cc or cc == "-99":
            continue
        g = feat["geometry"]
        polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
        ring = max((poly[0] for poly in polys), key=len)
        out[cc] = (sum(pt[1] for pt in ring) / len(ring), sum(pt[0] for pt in ring) / len(ring))
    return out


STATE = {"updated": None, "error": None}
LOCK = threading.Lock()


def build_state(geo, raw):
    attackers = []
    for r in raw["attackers"]:
        cc, lat, lng = geo.locate(r["source"])
        if lat is not None:
            attackers.append({"ip": r["source"], "cc": cc, "lat": lat, "lng": lng, "reports": r["reports"], "targets": r["targets"]})
    ports = [{"port": v["targetport"], "records": v["records"], "sources": v["sources"]}
             for k, v in raw["ports"].items() if k.isdigit()]
    c2 = []
    for r in raw["c2"]:
        cc, lat, lng = geo.locate(r["ip_address"])
        if lat is not None:
            c2.append({"ip": r["ip_address"], "port": r["port"], "cc": r.get("country") or cc, "lat": lat, "lng": lng,
                       "status": r["status"], "malware": r["malware"], "as": r.get("as_name"), "last_online": r.get("last_online")})
    vulns = sorted(raw["kev"]["vulnerabilities"], key=lambda v: v["dateAdded"], reverse=True)[:20]
    kev = [{k: v[k] for k in ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "knownRansomwareCampaignUse")} for v in vulns]
    return {"updated": int(time.time()), "error": None, "infocon": raw["infocon"].get("status", "unknown"),
            "attackers": attackers, "ports": ports, "c2": c2, "kev": kev, "kev_total": raw["kev"]["count"]}


def poll(geo):
    while True:
        try:
            raw = {k: json.loads(fetch(u)) for k, u in FEEDS.items()}
            new = build_state(geo, raw)
            with LOCK:
                STATE.clear(); STATE.update(new)
            print(time.strftime("%H:%M:%S"), f"refreshed: {len(new['attackers'])} attackers, {len(new['c2'])} C2, infocon {new['infocon']}")
        except Exception as e:  # keep serving the last good state
            with LOCK:
                STATE["error"] = f"{type(e).__name__}: {e}"
            print("poll failed:", e)
        time.sleep(REFRESH)


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=os.path.join(ROOT, "web"), **kw)

    def do_GET(self):
        if self.path.split("?")[0] == "/api/state":
            with LOCK:
                body = json.dumps(STATE).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        else:
            super().do_GET()

    def log_message(self, *a):
        pass


def selftest():
    geo = Geo([(16777216, 16777471, "AU"), (167772160, 184549375, "XX")], {"AU": (-25.0, 134.0)})
    assert geo.country("1.0.0.7") == "AU"
    assert geo.country("1.0.1.0") is None
    assert geo.country("not-an-ip") is None
    cc, lat, lng = geo.locate("1.0.0.7")
    assert cc == "AU" and abs(lat + 25) <= 3 and abs(lng - 134) <= 4
    assert geo.locate("10.0.0.1") == ("XX", None, None)
    sq = {"type": "Feature", "properties": {"ISO_A2": "-99", "ISO_A2_EH": "FR"},
          "geometry": {"type": "Polygon", "coordinates": [[[0, 40], [10, 40], [10, 50], [0, 50]]]}}
    assert centroids_from_geojson({"features": [sq]}) == {"FR": (45.0, 5.0)}
    raw = {"attackers": [{"source": "1.0.0.7", "reports": 9, "targets": 2}, {"source": "8.8.8.8", "reports": 1, "targets": 1}],
           "ports": {"0": {"targetport": 22, "records": 5, "sources": 1}, "date": "x"}, "infocon": {"status": "green"},
           "c2": [{"ip_address": "1.0.0.9", "port": 443, "status": "offline", "malware": "Emotet", "country": "AU"}],
           "kev": {"count": 1, "vulnerabilities": [{"cveID": "CVE-1", "vendorProject": "v", "product": "p", "vulnerabilityName": "n",
                                                   "dateAdded": "2026-01-01", "knownRansomwareCampaignUse": "Unknown"}]}}
    s = build_state(geo, raw)
    assert [a["ip"] for a in s["attackers"]] == ["1.0.0.7"]  # unlocatable IP dropped
    assert s["ports"] == [{"port": 22, "records": 5, "sources": 1}] and s["c2"][0]["status"] == "offline"
    print("selftest ok")


if __name__ == "__main__":
    if sys.argv[1:] == ["test"]:
        selftest(); sys.exit()
    print("loading geolocation db...")
    geo = load_geo()
    threading.Thread(target=poll, args=(geo,), daemon=True).start()
    port = int(os.environ.get("PORT", 8787))
    print(f"threatmap on http://127.0.0.1:{port}")
    http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
