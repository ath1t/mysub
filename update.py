"""Collect public subscription lists -> dedupe -> health check -> tag by country -> write outputs.

Outputs (all Base64 subscriptions unless noted):
  sub                 all nodes
  nodes.txt           all nodes, plain text
  country/<CC>.txt    nodes for one country (e.g. country/US.txt)
  COUNTRIES.md        index with links (auto-generated)
"""
import base64, json, os, socket, sys, urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlsplit

PROTOS = ("ss://", "vmess://", "vless://", "trojan://", "hysteria2://", "hy2://", "tuic://")
UDP_PROTOS = ("hysteria2://", "hy2://", "tuic://")  # cannot be checked with TCP
CHECK = os.getenv("CHECK", "1") == "1"
MAX_PER_COUNTRY = int(os.getenv("MAX_PER_COUNTRY", "100"))
MAX_TOTAL = int(os.getenv("MAX_TOTAL", "2000"))
GEO_DB = os.getenv("GEO_DB", "geo.mmdb")
# Set repository path directly to ath1t/mysub
REPO = os.getenv("GITHUB_REPOSITORY", "ath1t/mysub")


def fetch(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", "ignore").strip()
    except Exception as e:
        print(f"skip {url}: {e}", file=sys.stderr)
        return ""


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")


def b64e(s):
    return base64.b64encode(s.encode()).decode()


def extract(text):
    if not any(p in text for p in PROTOS):
        try:
            text = b64d(text)
        except Exception:
            return []
    return [l.strip() for l in text.splitlines() if l.strip().startswith(PROTOS)]


def host_port(link):
    try:
        if link.startswith("vmess://"):
            j = json.loads(b64d(link[8:]))
            return str(j["add"]), int(j["port"])
        body = link.split("#")[0]
        u = urlsplit(body)
        if u.hostname and u.port:
            return u.hostname, u.port
        if link.startswith("ss://"):  # legacy fully base64 form
            h, p = b64d(body[5:]).rsplit("@", 1)[1].rsplit(":", 1)
            return h, int(p)
    except Exception:
        pass
    return None


def probe(link):
    """Return (keep, ip). DNS-resolves the host; TCP-checks non-UDP protocols."""
    hp = host_port(link)
    if hp is None:
        return False, None
    host, port = hp
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return False, None
    if CHECK and not link.startswith(UDP_PROTOS):
        try:
            socket.create_connection((ip, port), timeout=4).close()
        except Exception:
            return False, ip
    return True, ip


def load_geo():
    try:
        import maxminddb
        return maxminddb.open_database(GEO_DB)
    except Exception as e:
        print(f"no geo database ({e}); everything goes to 'XX'", file=sys.stderr)
        return None


def country_of(geo, ip):
    if geo is None or ip is None:
        return "XX", "Unknown"
    try:
        record = geo.get(ip)
        if record and "country" in record:
            c = record["country"]
            iso = c.get("iso_code", "XX")
            name = c.get("names", {}).get("en", "Unknown")
            return iso, name
    except Exception:
        pass
    return "XX", "Unknown"


def flag(cc):
    return "🌐" if cc == "XX" else "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc)


def rename(link, name):
    if link.startswith("vmess://"):
        try:
            j = json.loads(b64d(link[8:]))
            j["ps"] = name
            return "vmess://" + b64e(json.dumps(j, ensure_ascii=False))
        except Exception:
            return link
    return link.split("#")[0] + "#" + quote(name)


def main():
    if not os.path.exists("sources.txt"):
        print("sources.txt not found!", file=sys.stderr)
        return

    urls = [l.strip() for l in open("sources.txt") if l.strip() and not l.startswith("#")]
    seen, nodes = set(), []
    for url in urls:
        got = extract(fetch(url))
        print(f"{len(got):5d} links  {url}")
        for link in got:
            key = link.split("#")[0]
            if key not in seen:
                seen.add(key)
                nodes.append(link)
    print(f"{len(nodes)} unique nodes")
    if not nodes:
        print("nothing collected; keeping previous files")
        return

    with ThreadPoolExecutor(100) as ex:
        results = list(ex.map(probe, nodes))
    geo = load_geo()

    by_cc, names = defaultdict(list), {}
    for link, (ok, ip) in zip(nodes, results):
        if not ok:
            continue
        cc, name = country_of(geo, ip)
        names[cc] = name
        proto = link.split("://")[0]
        by_cc[cc].append((link, proto))
    print(f"{sum(len(v) for v in by_cc.values())} usable nodes in {len(by_cc)} countries")

    all_nodes, per_country = [], {}
    for cc in sorted(by_cc):
        tagged = []
        for i, (link, proto) in enumerate(by_cc[cc][:MAX_PER_COUNTRY], 1):
            tagged.append(rename(link, f"{flag(cc)} {cc}-{i:03d} {proto}"))
        per_country[cc] = tagged
        all_nodes += tagged
    all_nodes = all_nodes[:MAX_TOTAL]
    if not all_nodes:
        print("no usable nodes; keeping previous files")
        return

    os.makedirs("country", exist_ok=True)
    for f in os.listdir("country"):
        fp = os.path.join("country", f)
        if os.path.isfile(fp):
            os.remove(fp)

    open("nodes.txt", "w", encoding="utf-8").write("\n".join(all_nodes) + "\n")
    open("sub", "w", encoding="utf-8").write(b64e("\n".join(all_nodes)))
    for cc, lst in per_country.items():
        if cc != "XX":
            open(f"country/{cc}.txt", "w", encoding="utf-8").write(b64e("\n".join(lst)))

    base = f"https://raw.githubusercontent.com/{REPO}/main"
    rows = ["# Subscription links", "",
            f"All countries: `{base}/sub`", "",
            "| Country | Nodes | Subscription link |", "| --- | --: | --- |"]
    for cc, lst in sorted(per_country.items(), key=lambda kv: -len(kv[1])):
        if cc != "XX":
            rows.append(f"| {flag(cc)} {names.get(cc, 'Unknown')} ({cc}) | {len(lst)} | `{base}/country/{cc}.txt` |")
    open("COUNTRIES.md", "w", encoding="utf-8").write("\n".join(rows) + "\n")


if __name__ == "__main__":
    main()
