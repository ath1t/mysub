#!/usr/bin/env python3

"""
Public Proxy Subscription Collector
====================================

Pipeline:
1. Fetch public subscription sources.
2. Monitor source availability.
3. Extract supported protocols.
4. Deduplicate nodes.
5. Resolve DNS and test TCP connectivity.
6. Measure TCP connection latency.
7. Detect server country using MaxMind GeoIP.
8. Generate country-specific subscriptions.
9. Rank the fastest 100 TCP nodes.

Outputs:
    sub                 All nodes (Base64)
    nodes.txt           All nodes (plain text)
    top100.txt          Fastest 100 TCP nodes (Base64)
    TOP100.md           Latency ranking report
    COUNTRIES.md        Country subscription index
    country/<CC>.txt    Country nodes (Base64)
"""

import base64
import ipaddress
import json
import os
import socket
import statistics
import sys
import time
import urllib.error
import urllib.request

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, unquote, urlsplit


# ============================================================
# CONFIGURATION
# ============================================================

PROTOS = (
    "ss://",
    "vmess://",
    "vless://",
    "trojan://",
    "hysteria2://",
    "hy2://",
    "tuic://",
)

UDP_PROTOS = (
    "hysteria2://",
    "hy2://",
    "tuic://",
)

PROTOCOL_NAMES = {
    "ss": "Shadowsocks",
    "vmess": "VMess",
    "vless": "VLESS",
    "trojan": "Trojan",
    "hysteria2": "Hysteria2",
    "hy2": "Hysteria2",
    "tuic": "TUIC",
}

CHECK = os.getenv("CHECK", "1") == "1"

MAX_PER_COUNTRY = int(
    os.getenv("MAX_PER_COUNTRY", "100")
)

MAX_TOTAL = int(
    os.getenv("MAX_TOTAL", "2000")
)

TOP_N = int(
    os.getenv("TOP_N", "100")
)

PING_ATTEMPTS = int(
    os.getenv("PING_ATTEMPTS", "3")
)

PING_TIMEOUT = float(
    os.getenv("PING_TIMEOUT", "4")
)

MAX_WORKERS = int(
    os.getenv("MAX_WORKERS", "100")
)

SOURCE_TIMEOUT = int(
    os.getenv("SOURCE_TIMEOUT", "30")
)

GEO_DB = os.getenv("GEO_DB", "geo.mmdb")

REPO = os.getenv(
    "GITHUB_REPOSITORY",
    "ath1t/mysub"
)

BRANCH = os.getenv(
    "GITHUB_REF_NAME",
    "main"
)

USER_AGENT = "Mozilla/5.0 (compatible; PublicSubscriptionCollector/1.0)"


# ============================================================
# BASE64 UTILITIES
# ============================================================

def b64d(value):
    value = value.strip()
    value = value.replace("-", "+").replace("_", "/")

    value += "=" * (-len(value) % 4)

    return base64.b64decode(
        value,
        validate=True
    ).decode("utf-8", "ignore")


def b64e(value):
    return base64.b64encode(
        value.encode("utf-8")
    ).decode("ascii")


# ============================================================
# SOURCE FETCHING
# ============================================================

def fetch(url):
    """
    Returns:
        content, HTTP status, error
    """

    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
            },
        )

        with urllib.request.urlopen(
            request,
            timeout=SOURCE_TIMEOUT
        ) as response:

            content = response.read().decode(
                "utf-8",
                "ignore"
            ).strip()

            return content, response.status, None

    except urllib.error.HTTPError as error:

        return "", error.code, f"HTTP {error.code}"

    except urllib.error.URLError as error:

        return "", 0, str(error.reason)

    except Exception as error:

        return "", 0, str(error)


# ============================================================
# SUBSCRIPTION EXTRACTION
# ============================================================

def extract(text):
    """
    Supports:
        Plain-text subscriptions
        Base64 subscriptions
        Multiple supported protocol links
    """

    if not text:
        return []

    # Try decoding only when no supported protocol exists.
    if not any(proto in text for proto in PROTOS):

        try:
            decoded = b64d(text)

            if any(proto in decoded for proto in PROTOS):
                text = decoded
            else:
                return []

        except Exception:
            return []

    results = []

    for line in text.splitlines():

        line = line.strip()

        if line.startswith(PROTOS):
            results.append(line)

    return results


# ============================================================
# NODE PARSING
# ============================================================

def host_port(link):

    try:

        # VMess JSON
        if link.startswith("vmess://"):

            data = json.loads(
                b64d(link[8:])
            )

            host = str(data["add"])
            port = int(data["port"])

            return host, port

        body = link.split("#", 1)[0]

        # Standard URI formats
        parsed = urlsplit(body)

        if parsed.hostname and parsed.port:

            return parsed.hostname, parsed.port

        # Legacy Shadowsocks format:
        # ss://BASE64(method:password@host:port)
        if link.startswith("ss://"):

            encoded = body[5:]

            # Remove SIP002 query parameters if present.
            encoded = encoded.split("?", 1)[0]

            decoded = b64d(encoded)

            endpoint = decoded.rsplit("@", 1)[1]

            # Handle IPv6 endpoints.
            if endpoint.startswith("["):

                parsed_endpoint = urlsplit(
                    "//" + endpoint
                )

                return (
                    parsed_endpoint.hostname,
                    parsed_endpoint.port
                )

            host, port = endpoint.rsplit(":", 1)

            return host, int(port)

    except Exception:
        pass

    return None


# ============================================================
# LATENCY AND HEALTH CHECK
# ============================================================

def probe(link):
    """
    Returns:
        healthy, ip, latency_ms, error

    Latency is measured using TCP connect time,
    NOT ICMP ping.

    UDP protocols receive DNS checks only and
    are excluded from TCP latency ranking.
    """

    endpoint = host_port(link)

    if endpoint is None:

        return False, None, None, "Invalid node format"

    host, port = endpoint

    if not host or not (1 <= port <= 65535):

        return False, None, None, "Invalid host or port"

    try:

        addresses = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM
        )

        if not addresses:

            return False, None, None, "DNS returned no addresses"

    except Exception as error:

        return False, None, None, f"DNS failed: {error}"

    # Try available addresses until one resolves successfully.
    selected = None

    for address in addresses:

        family, socktype, proto, _, sockaddr = address

        try:

            ip = str(
                ipaddress.ip_address(sockaddr[0])
            )

            selected = (
                family,
                socktype,
                proto,
                sockaddr,
                ip
            )

            break

        except ValueError:
            continue

    if selected is None:

        return False, None, None, "Invalid IP address"

    family, socktype, proto, sockaddr, ip = selected

    # UDP protocols cannot be tested using TCP.
    if link.startswith(UDP_PROTOS):

        return True, ip, None, None

    if not CHECK:

        return True, ip, None, None

    measurements = []

    for attempt in range(max(1, PING_ATTEMPTS)):

        sock = socket.socket(
            family,
            socktype,
            proto
        )

        sock.settimeout(PING_TIMEOUT)

        start = time.perf_counter()

        try:

            sock.connect(sockaddr)

            elapsed = (
                time.perf_counter() - start
            ) * 1000

            measurements.append(elapsed)

        except Exception:

            pass

        finally:

            sock.close()

    if not measurements:

        return False, ip, None, "TCP connection failed"

    latency = statistics.median(measurements)

    return True, ip, latency, None


# ============================================================
# GEOLOCATION
# ============================================================

def load_geo():

    try:

        import maxminddb

        if not os.path.exists(GEO_DB):

            raise FileNotFoundError(GEO_DB)

        return maxminddb.open_database(GEO_DB)

    except Exception as error:

        print(
            f"[WARNING] GeoIP unavailable: {error}",
            file=sys.stderr
        )

        return None


def country_of(geo, ip):

    if geo is None or ip is None:

        return "XX", "Unknown"

    try:

        record = geo.get(ip)

        if not record:

            return "XX", "Unknown"

        # Prefer country, fall back to registered country.
        country = (
            record.get("country")
            or record.get("registered_country")
            or {}
        )

        code = country.get("iso_code", "XX")

        name = country.get(
            "names", {}
        ).get("en", "Unknown")

        return code, name

    except Exception:

        return "XX", "Unknown"


# ============================================================
# COUNTRY FLAGS
# ============================================================

def flag(cc):

    if (
        len(cc) != 2
        or not cc.isalpha()
        or cc == "XX"
    ):

        return "🌐"

    return "".join(
        chr(0x1F1E6 + ord(char.upper()) - 65)
        for char in cc
    )


# ============================================================
# NODE NAMING
# ============================================================

def rename(link, name):

    if link.startswith("vmess://"):

        try:

            data = json.loads(
                b64d(link[8:])
            )

            data["ps"] = name

            return (
                "vmess://"
                + b64e(
                    json.dumps(
                        data,
                        ensure_ascii=False
                    )
                )
            )

        except Exception:

            return link

    return (
        link.split("#", 1)[0]
        + "#"
        + quote(name, safe="")
    )


# ============================================================
# OUTPUT UTILITIES
# ============================================================

def write_file(path, content):

    with open(
        path,
        "w",
        encoding="utf-8",
        newline="\n"
    ) as file:

        file.write(content)


def write_subscription(path, nodes):

    write_file(
        path,
        b64e("\n".join(nodes))
    )


# ============================================================
# SOURCE HEALTH MONITOR
# ============================================================

def collect_sources(urls):

    seen = set()
    nodes = []

    stats = {
        "working": 0,
        "empty": 0,
        "failed": 0,
    }

    print("\n========== SOURCE HEALTH ==========")

    for url in urls:

        content, status, error = fetch(url)

        if error:

            stats["failed"] += 1

            print(
                f"[FAILED] HTTP {status} | {url}"
            )

            print(
                f"         Reason: {error}"
            )

            continue

        extracted = extract(content)

        if not extracted:

            stats["empty"] += 1

            print(
                f"[EMPTY]  HTTP {status} | {url}"
            )

            continue

        stats["working"] += 1

        new_count = 0

        for link in extracted:

            key = link.split("#", 1)[0]

            if key not in seen:

                seen.add(key)
                nodes.append(link)

                new_count += 1

        print(
            f"[OK] HTTP {status} | "
            f"{len(extracted)} links | "
            f"{new_count} new | {url}"
        )

    print("\n========== SOURCE SUMMARY ==========")

    print(f"Working sources : {stats['working']}")
    print(f"Empty sources   : {stats['empty']}")
    print(f"Failed sources  : {stats['failed']}")
    print(f"Unique nodes    : {len(nodes)}")

    return nodes, stats


# ============================================================
# NODE TESTING
# ============================================================

def test_nodes(nodes):

    print("\n========== NODE HEALTH CHECK ==========\n")

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        results = list(
            executor.map(probe, nodes)
        )

    return results


# ============================================================
# MAIN
# ============================================================

def main():

    if not os.path.exists("sources.txt"):

        print("[ERROR] sources.txt not found")

        return

    with open(
        "sources.txt",
        encoding="utf-8"
    ) as file:

        urls = [
            line.strip()
            for line in file
            if line.strip()
            and not line.lstrip().startswith("#")
        ]

    if not urls:

        print("[ERROR] No source URLs found")

        return

    # --------------------------------------------------------
    # COLLECT SOURCES
    # --------------------------------------------------------

    nodes, source_stats = collect_sources(urls)

    if not nodes:

        print(
            "\nNo nodes collected. "
            "Previous outputs preserved."
        )

        return

    # --------------------------------------------------------
    # TEST NODES
    # --------------------------------------------------------

    results = test_nodes(nodes)

    geo = load_geo()

    by_cc = defaultdict(list)
    country_names = {}

    healthy = 0
    measured = 0
    failed = 0
    udp_count = 0

    print("\n========== NODE RESULTS ==========\n")

    for link, result in zip(nodes, results):

        ok, ip, latency, error = result

        if not ok:

            failed += 1
            continue

        healthy += 1

        if latency is not None:

            measured += 1

        else:

            udp_count += 1

        cc, name = country_of(geo, ip)

        country_names[cc] = name

        proto = link.split("://", 1)[0].lower()

        by_cc[cc].append({
            "link": link,
            "proto": proto,
            "latency": latency,
        })

    if geo:

        geo.close()

    print(f"Healthy nodes       : {healthy}")
    print(f"Failed nodes        : {failed}")
    print(f"TCP latency tested  : {measured}")
    print(f"UDP nodes           : {udp_count}")
    print(f"Countries detected  : {len(by_cc)}")

    if healthy == 0:

        print(
            "\nNo healthy nodes. "
            "Previous outputs preserved."
        )

        return

    # --------------------------------------------------------
    # SORT COUNTRY NODES
    # --------------------------------------------------------

    per_country = {}
    all_nodes = []
    ranked_candidates = []

    for cc in sorted(by_cc):

        country_nodes = sorted(
            by_cc[cc],
            key=lambda item: (
                item["latency"] is None,
                item["latency"]
                if item["latency"] is not None
                else float("inf")
            )
        )

        country_nodes = country_nodes[
            :MAX_PER_COUNTRY
        ]

        tagged = []

        for index, item in enumerate(
            country_nodes,
            1
        ):

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

            node_name = (
                f"{flag(cc)} {cc}-{index:03d} "
                f"{proto} {latency_label}"
            )

            tagged_link = rename(
                item["link"],
                node_name
            )

            tagged.append(tagged_link)

            if latency is not None:

                ranked_candidates.append({
                    "link": tagged_link,
                    "latency": latency,
                    "country": cc,
                    "protocol": proto,
                })

        per_country[cc] = tagged

        all_nodes.extend(tagged)

    # --------------------------------------------------------
    # GLOBAL NODE LIMIT
    # --------------------------------------------------------

    all_nodes = all_nodes[:MAX_TOTAL]

    # --------------------------------------------------------
    # TOP 100 LATENCY RANKING
    # --------------------------------------------------------

    ranked_candidates.sort(
        key=lambda item: item["latency"]
    )

    top_nodes = ranked_candidates[:TOP_N]

    # --------------------------------------------------------
    # WRITE OUTPUTS
    # --------------------------------------------------------

    os.makedirs("country", exist_ok=True)

    # Remove stale country files.
    for filename in os.listdir("country"):

        filepath = os.path.join(
            "country",
            filename
        )

        if os.path.isfile(filepath):

            os.remove(filepath)

    # All nodes - plain text
    write_file(
        "nodes.txt",
        "\n".join(all_nodes) + "\n"
    )

    # All nodes - Base64
    write_subscription(
        "sub",
        all_nodes
    )

    # Country subscriptions - Base64
    for cc, country_nodes in per_country.items():

        if cc == "XX":
            continue

        write_subscription(
            f"country/{cc}.txt",
            country_nodes
        )

    # Top 100 - Base64
    top_links = [
        item["link"]
        for item in top_nodes
    ]

    write_subscription(
        "top100.txt",
        top_links
    )

    # --------------------------------------------------------
    # TOP 100 REPORT
    # --------------------------------------------------------

    report = [
        "# Top 100 Fastest Nodes",
        "",
        "> TCP connection latency measured from GitHub Actions.",
        "> This is not Myanmar ISP latency or ICMP ping.",
        "",
        f"Total ranked nodes: {len(top_nodes)}",
        "",
        "| Rank | Country | Protocol | Latency (ms) |",
        "| ---: | --- | --- | ---: |",
    ]

    for rank, item in enumerate(
        top_nodes,
        1
    ):

        cc = item["country"]

        report.append(
            f"| {rank} "
            f"| {flag(cc)} {cc} "
            f"| {item['protocol']} "
            f"| {item['latency']:.2f} |"
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
        f"{REPO}/{BRANCH}"
    )

    rows = [
        "# Subscription links",
        "",
        f"All countries: `{base}/sub`",
        "",
        f"Fastest {TOP_N} TCP nodes: `{base}/top100.txt`",
        "",
        "## Country subscriptions",
        "",
        "| Country | Nodes | Subscription link |",
        "| --- | ---: | --- |",
    ]

    for cc, country_nodes in sorted(
        per_country.items(),
        key=lambda item: -len(item[1])
    ):

        if cc == "XX":

            continue

        rows.append(
            f"| {flag(cc)} "
            f"{country_names.get(cc, 'Unknown')} ({cc}) "
            f"| {len(country_nodes)} "
            f"| `{base}/country/{cc}.txt` |"
        )

    rows.extend([
        "",
        "## Latency ranking",
        "",
        "[View TOP 100 report](TOP100.md)",
        "",
        "## Source health",
        "",
        f"- Working: {source_stats['working']}",
        f"- Empty: {source_stats['empty']}",
        f"- Failed: {source_stats['failed']}",
        "",
    ])

    write_file(
        "COUNTRIES.md",
        "\n".join(rows)
    )

    # --------------------------------------------------------
    # FINAL SUMMARY
    # --------------------------------------------------------

    print("\n========== OUTPUT SUMMARY ==========")

    print(f"All nodes       : {len(all_nodes)}")
    print(f"Top TCP nodes   : {len(top_nodes)}")
    print(f"Country files   : {len(per_country)}")

    print("\n========== FASTEST 10 ==========\n")

    for rank, item in enumerate(
        top_nodes[:10],
        1
    ):

        print(
            f"{rank:02d}. "
            f"{flag(item['country'])} "
            f"{item['country']} "
            f"{item['protocol']} "
            f"{item['latency']:.2f} ms"
        )

    print("\n[OK] Subscription generation completed.")


if __name__ == "__main__":

    main()
