
import base64
import json
import os
import socket
import sys
import time
import statistics
import shutil
import urllib.request

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlsplit

# ============================================================
# CONFIGURATION
# ============================================================

PROTOS = (
    "ss://", "vmess://", "vless://", "trojan://",
    "hysteria2://", "hy2://", "tuic://"
)

UDP_PROTOS = ("hysteria2://", "hy2://", "tuic://")

CHECK = os.getenv("CHECK", "1") == "1"

MAX_PER_COUNTRY = int(os.getenv("MAX_PER_COUNTRY", "100"))
MAX_TOTAL = int(os.getenv("MAX_TOTAL", "2000"))
TOP_N = int(os.getenv("TOP_N", "100"))

PING_ATTEMPTS = int(os.getenv("PING_ATTEMPTS", "3"))
PING_TIMEOUT = float(os.getenv("PING_TIMEOUT", "4"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "100"))

GEO_DB = os.getenv("GEO_DB", "geo.mmdb")
REPO = os.getenv("GITHUB_REPOSITORY", "ath1t/mysub")

PROTOCOL_NAMES = {
    "ss": "Shadowsocks",
    "vmess": "VMess",
    "vless": "VLESS",
    "trojan": "Trojan",
    "hysteria2": "Hysteria2",
    "hy2": "Hysteria2",
    "tuic": "TUIC",
}


# ============================================================
# BASE64
# ============================================================

def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(
        s + "=" * (-len(s) % 4)
    ).decode("utf-8", "ignore")


def b64e(s):
    return base64.b64encode(s.encode()).decode()


# ============================================================
# FETCH SUBSCRIPTIONS
# ============================================================

def fetch(url):
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", "ignore").strip()

    except Exception as e:
        print(f"skip {url}: {e}", file=sys.stderr)
        return ""


def extract(text):
    if not any(p in text for p in PROTOS):
        try:
            text = b64d(text)
        except Exception:
            return []

    return [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith(PROTOS)
    ]


# ============================================================
# NODE PARSER
# ============================================================

def host_port(link):
    try:
        if link.startswith("vmess://"):
            data = json.loads(b64d(link[8:]))
            return str(data["add"]), int(data["port"])

        body = link.split("#")[0]
        u = urlsplit(body)

        if u.hostname and u.port:
            return u.hostname, u.port

        # Legacy Shadowsocks Base64 format
        if link.startswith("ss://"):
            decoded = b64d(body[5:])
            endpoint = decoded.rsplit("@", 1)[1]
            host, port = endpoint.rsplit(":", 1)
            return host, int(port)

    except Exception:
        pass

    return None


# ============================================================
# LATENCY / TCP HEALTH CHECK
# ============================================================

def probe(link):
    """
    Returns:
        (healthy, ip, latency_ms)

    TCP protocols:
        DNS + repeated TCP connection measurements.

    UDP protocols:
        DNS only. No TCP latency is assigned.
    """

    hp = host_port(link)

    if hp is None:
        return False, None, None

    host, port = hp

    try:
        addresses = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM
        )

        if not addresses:
            return False, None, None

        family, socktype, proto, _, sockaddr = addresses[0]
        ip = sockaddr[0]

    except Exception:
        return False, None, None

    # UDP protocols cannot be measured using TCP connect.
    if link.startswith(UDP_PROTOS):
        return True, ip, None

    if not CHECK:
        return True, ip, None

    measurements = []

    for _ in range(PING_ATTEMPTS):
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(PING_TIMEOUT)

        start = time.perf_counter()

        try:
            sock.connect(sockaddr)

            elapsed = (time.perf_counter() - start) * 1000
            measurements.append(elapsed)

        except Exception:
            pass

        finally:
            sock.close()

    if not measurements:
        return False, ip, None

    latency = statistics.median(measurements)

    return True, ip, latency


# ============================================================
# GEOLOCATION
# ============================================================

def load_geo():
    try:
        import maxminddb
        return maxminddb.open_database(GEO_DB)

    except Exception as e:
        print(f"Geo database unavailable: {e}", file=sys.stderr)
        return None


def country_of(geo, ip):
    if geo is None or ip is None:
        return "XX", "Unknown"

    try:
        record = geo.get(ip)

        if record and "country" in record:
            country = record["country"]

            return (
                country.get("iso_code", "XX"),
                country.get("names", {}).get("en", "Unknown")
            )

    except Exception:
        pass

    return "XX", "Unknown"


def flag(cc):
    if cc == "XX":
        return "🌐"

    return "".join(
        chr(0x1F1E6 + ord(c) - 65)
        for c in cc
    )


# ============================================================
# NODE NAMING
# ============================================================

def rename(link, name):
    if link.startswith("vmess://"):
        try:
            data = json.loads(b64d(link[8:]))
            data["ps"] = name

            return "vmess://" + b64e(
                json.dumps(data, ensure_ascii=False)
            )

        except Exception:
            return link

    return link.split("#")[0] + "#" + quote(name)


# ============================================================
# OUTPUT
# ============================================================

def write_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def main():

    if not os.path.exists("sources.txt"):
        print("sources.txt not found!")
        return

    with open("sources.txt", encoding="utf-8") as f:
        urls = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]

    # --------------------------------------------------------
    # COLLECT + DEDUPLICATE
    # --------------------------------------------------------

    seen = set()
    nodes = []

    for url in urls:
        got = extract(fetch(url))
        print(f"{len(got):5d} links  {url}")

        for link in got:
            key = link.split("#")[0]

            if key not in seen:
                seen.add(key)
                nodes.append(link)

    print(f"\n{len(nodes)} unique nodes collected")

    if not nodes:
        print("Nothing collected; keeping previous files")
        return

    # --------------------------------------------------------
    # PARALLEL LATENCY TEST
    # --------------------------------------------------------

    print("\nTesting nodes...")

    with ThreadPoolExecutor(MAX_WORKERS) as executor:
        results = list(executor.map(probe, nodes))

    geo = load_geo()

    by_cc = defaultdict(list)
    names = {}

    healthy = 0
    measured = 0

    for link, (ok, ip, latency) in zip(nodes, results):

        if not ok:
            continue

        cc, country_name = country_of(geo, ip)

        names[cc] = country_name

        proto = link.split("://", 1)[0].lower()

        by_cc[cc].append({
            "link": link,
            "proto": proto,
            "latency": latency,
        })

        healthy += 1

        if latency is not None:
            measured += 1

    if geo:
        geo.close()

    print(f"Healthy nodes: {healthy}")
    print(f"TCP latency measured: {measured}")
    print(f"Countries found: {len(by_cc)}")

    # --------------------------------------------------------
    # SORT EACH COUNTRY BY LATENCY
    # --------------------------------------------------------

    all_nodes = []
    ranked_candidates = []
    per_country = {}

    for cc in sorted(by_cc):

        country_nodes = sorted(
            by_cc[cc],
            key=lambda x: (
                x["latency"] is None,
                x["latency"] if x["latency"] is not None else float("inf")
            )
        )

        country_nodes = country_nodes[:MAX_PER_COUNTRY]

        tagged = []

        for i, item in enumerate(country_nodes, 1):

            proto = PROTOCOL_NAMES.get(
                item["proto"],
                item["proto"].upper()
            )

            latency = item["latency"]

            latency_label = (
                f"{latency:.0f}ms"
                if latency is not None
                else "UDP"
            )

            name = (
                f"{flag(cc)} {cc}-{i:03d} "
                f"{proto} {latency_label}"
            )

            tagged_link = rename(item["link"], name)

            tagged.append(tagged_link)

            if latency is not None:
                ranked_candidates.append({
                    "link": tagged_link,
                    "latency": latency,
                    "country": cc,
                })

        per_country[cc] = tagged
        all_nodes.extend(tagged)

    # --------------------------------------------------------
    # GLOBAL TOP 100
    # --------------------------------------------------------

    ranked_candidates.sort(
        key=lambda x: x["latency"]
    )

    top_nodes = ranked_candidates[:TOP_N]

    all_nodes = all_nodes[:MAX_TOTAL]

    if not all_nodes:
        print("No usable nodes; keeping previous files")
        return

    # --------------------------------------------------------
    # WRITE FILES
    # --------------------------------------------------------

    os.makedirs("country", exist_ok=True)

    # Remove previous country outputs
    for filename in os.listdir("country"):
        filepath = os.path.join("country", filename)

        if os.path.isfile(filepath):
            os.remove(filepath)

    # All nodes: plain text
    write_file(
        "nodes.txt",
        "\n".join(all_nodes) + "\n"
    )

    # All nodes: Base64 subscription
    write_file(
        "sub",
        b64e("\n".join(all_nodes))
    )

    # Country subscriptions: Base64
    for cc, country_list in per_country.items():

        if cc == "XX":
            continue

        write_file(
            f"country/{cc}.txt",
            b64e("\n".join(country_list))
        )

    # Top 100: Base64 subscription
    write_file(
        "top100.txt",
        b64e("\n".join(item["link"] for item in top_nodes))
    )

    # Human-readable latency report
    report = [
        "# Myanmar Network - Top 100 Node Latency",
        "",
        "| Rank | Country | Latency (ms) | Node |",
        "| ---: | --- | ---: | --- |",
    ]

    for rank, item in enumerate(top_nodes, 1):

        cc = item["country"]
        latency = item["latency"]

        report.append(
            f"| {rank} | {flag(cc)} {cc} "
            f"| {latency:.2f} | {rank:03d} |"
        )

    write_file(
        "TOP100.md",
        "\n".join(report) + "\n"
    )

    # --------------------------------------------------------
    # COUNTRY INDEX
    # --------------------------------------------------------

    base = (
        f"https://raw.githubusercontent.com/"
        f"{REPO}/main"
    )

    rows = [
        "# Subscription links",
        "",
        f"All countries: `{base}/sub`",
        "",
        f"Fastest {TOP_N} TCP nodes: `{base}/top100.txt`",
        "",
        "| Country | Nodes | Subscription link |",
        "| --- | ---: | --- |",
    ]

    for cc, country_list in sorted(
        per_country.items(),
        key=lambda item: -len(item[1])
    ):

        if cc == "XX":
            continue

        rows.append(
            f"| {flag(cc)} {names.get(cc, 'Unknown')} ({cc}) "
            f"| {len(country_list)} "
            f"| `{base}/country/{cc}.txt` |"
        )

    rows.extend([
        "",
        f"## Latency report",
        "",
        f"[View Top {TOP_N} latency ranking](TOP100.md)",
    ])

    write_file(
        "COUNTRIES.md",
        "\n".join(rows) + "\n"
    )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print("\n========== RESULTS ==========")
    print(f"All nodes: {len(all_nodes)}")
    print(f"Top {TOP_N}: {len(top_nodes)}")
    print(f"Country files: {len(per_country)}")

    if top_nodes:
        print("\nFASTEST NODES:")

        for i, item in enumerate(top_nodes[:10], 1):
            print(
                f"{i:02d}. {item['country']} "
                f"{item['latency']:.2f} ms"
            )

    print("\nOutput generation completed!")


if __name__ == "__main__":
    main()
