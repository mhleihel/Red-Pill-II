"""
ZAP spider seeder — reads routes.json and queues all discovered URLs into ZAP.

Prerequisites:
  - ZAP running in daemon mode: zap.sh -daemon -port 8090 -config api.key=booyah
  - routes.json from extract_routes.py

Usage:
  python3 zap_seed.py --routes routes.json --base-url http://localhost:8082 --zap-url http://localhost:8090 --api-key booyah
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path


def zap_api(zap_url: str, api_key: str, component: str, op_type: str, action: str, params: dict | None = None) -> dict:
    """Call the ZAP REST API."""
    url = f"{zap_url}/JSON/{component}/{op_type}/{action}/"
    query = {"apikey": api_key}
    if params:
        query.update(params)
    full_url = url + "?" + urllib.parse.urlencode(query)
    try:
        with urllib.request.urlopen(full_url, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        print(f"  ZAP API error ({action}): {e}", file=sys.stderr)
        return {}


def wait_for_zap(zap_url: str, api_key: str, timeout: int = 30) -> bool:
    """Wait until ZAP is ready."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            result = zap_api(zap_url, api_key, "core", "view", "version")
            if result.get("version"):
                print(f"  ZAP version: {result['version']}")
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def build_urls(routes: list[dict], base_url: str) -> list[dict]:
    """Expand routes.json entries into concrete URLs with parameter injection."""
    base_url = base_url.rstrip("/")
    urls = []
    seen = set()

    for route in routes:
        url_path = route.get("url", "")
        if not url_path or "<unmatched>" in url_path:
            continue

        # Base URL (no params)
        full_url = base_url + url_path
        if full_url not in seen:
            seen.add(full_url)
            urls.append({"url": full_url, "route": route, "params": {}})

        # URL with known GET params injected as fuzz values
        get_params = route.get("params_get", []) + route.get("params_request", [])
        if get_params:
            fuzz_params = {p: f"booyah_SEED_{p}" for p in get_params[:10]}
            parameterized = full_url + "?" + urllib.parse.urlencode(fuzz_params)
            if parameterized not in seen:
                seen.add(parameterized)
                urls.append({"url": parameterized, "route": route, "params": fuzz_params})

    return urls


def access_url(zap_url: str, api_key: str, url: str) -> bool:
    """Tell ZAP to access a URL (adds it to the site tree)."""
    result = zap_api(zap_url, api_key, "core", "action", "accessUrl", {"url": url, "followRedirects": "false"})
    return "Result" in result


def run_spider(zap_url: str, api_key: str, target_url: str, scan_id_out: list) -> int:
    """Start ZAP spider on the target and return scan ID."""
    result = zap_api(zap_url, api_key, "spider", "action", "scan", {
        "url": target_url,
        "maxChildren": "10",
        "recurse": "true",
        "contextName": "",
        "subtreeOnly": "false",
    })
    scan_id = int(result.get("scan", -1))
    scan_id_out.append(scan_id)
    return scan_id


def wait_for_spider(zap_url: str, api_key: str, scan_id: int, poll_interval: int = 5) -> None:
    """Poll until spider is done."""
    while True:
        result = zap_api(zap_url, api_key, "spider", "view", "status", {"scanId": str(scan_id)})
        status = int(result.get("status", 0))
        print(f"  Spider progress: {status}%", end="\r", flush=True)
        if status >= 100:
            print()
            break
        time.sleep(poll_interval)


def run_active_scan(zap_url: str, api_key: str, target_url: str) -> int:
    """Start ZAP active scan (XSS policy) and return scan ID."""
    result = zap_api(zap_url, api_key, "ascan", "action", "scan", {
        "url": target_url,
        "recurse": "true",
        "inScopeOnly": "false",
        "scanPolicyName": "",
        "method": "",
        "postData": "",
    })
    return int(result.get("scan", -1))


def wait_for_ascan(zap_url: str, api_key: str, scan_id: int, poll_interval: int = 10) -> None:
    """Poll until active scan is done."""
    while True:
        result = zap_api(zap_url, api_key, "ascan", "view", "status", {"scanId": str(scan_id)})
        status = int(result.get("status", 0))
        print(f"  Active scan progress: {status}%", end="\r", flush=True)
        if status >= 100:
            print()
            break
        time.sleep(poll_interval)


def get_alerts(zap_url: str, api_key: str, base_url: str) -> list[dict]:
    """Retrieve all XSS alerts from ZAP."""
    result = zap_api(zap_url, api_key, "alert", "view", "alertsByRisk", {
        "url": base_url,
        "recurse": "true",
    })
    alerts = []
    # alertsByRisk returns dict of risk -> list of alerts
    for risk_group in result.values():
        if isinstance(risk_group, list):
            for alert in risk_group:
                if isinstance(alert, dict) and "xss" in alert.get("name", "").lower():
                    alerts.append(alert)
    return alerts


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed ZAP with Magento routes and run XSS scan")
    parser.add_argument("--routes", required=True, help="Path to routes.json")
    parser.add_argument("--base-url", required=True, help="Magento base URL, e.g. http://localhost:8082")
    parser.add_argument("--zap-url", default="http://localhost:8090", help="ZAP API URL")
    parser.add_argument("--api-key", default="booyah", help="ZAP API key")
    parser.add_argument("--output", default="results/zap_alerts.json", help="Output JSON file")
    parser.add_argument("--no-active-scan", action="store_true", help="Skip active XSS scan")
    parser.add_argument("--access-only", action="store_true", help="Only access URLs, skip spider/ascan")
    args = parser.parse_args()

    routes_path = Path(args.routes)
    if not routes_path.exists():
        print(f"Routes file not found: {routes_path}", file=sys.stderr)
        sys.exit(1)

    with open(routes_path) as f:
        routes = json.load(f)

    print(f"[*] Loaded {len(routes)} routes from {routes_path}")

    print(f"[*] Waiting for ZAP at {args.zap_url}...")
    if not wait_for_zap(args.zap_url, args.api_key):
        print("ZAP not reachable — is it running?", file=sys.stderr)
        sys.exit(1)

    urls = build_urls(routes, args.base_url)
    print(f"[*] Expanded to {len(urls)} URLs")

    # Access all URLs to seed ZAP's site tree
    print("[*] Seeding ZAP site tree...")
    success = 0
    for i, entry in enumerate(urls):
        if access_url(args.zap_url, args.api_key, entry["url"]):
            success += 1
        if (i + 1) % 50 == 0:
            print(f"  Accessed {i + 1}/{len(urls)} URLs", end="\r", flush=True)
    print(f"\n[+] Accessed {success}/{len(urls)} URLs")

    if args.access_only:
        print("[*] --access-only set, stopping here")
        return

    # Spider
    print(f"[*] Starting ZAP spider on {args.base_url}...")
    scan_ids: list[int] = []
    scan_id = run_spider(args.zap_url, args.api_key, args.base_url, scan_ids)
    if scan_id >= 0:
        wait_for_spider(args.zap_url, args.api_key, scan_id)
        print(f"[+] Spider complete (scan ID {scan_id})")

    # Active scan
    if not args.no_active_scan:
        print(f"[*] Starting active XSS scan on {args.base_url}...")
        ascan_id = run_active_scan(args.zap_url, args.api_key, args.base_url)
        if ascan_id >= 0:
            wait_for_ascan(args.zap_url, args.api_key, ascan_id)
            print(f"[+] Active scan complete (scan ID {ascan_id})")

    # Collect alerts
    print("[*] Collecting XSS alerts...")
    alerts = get_alerts(args.zap_url, args.api_key, args.base_url)
    print(f"[+] Found {len(alerts)} XSS alerts")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"[+] Alerts written to {out_path}")


if __name__ == "__main__":
    main()
