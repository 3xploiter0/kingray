import requests
import json
from urllib.parse import urlparse


WAYBACK_API = "https://web.archive.org/cdx/search/cdx?url={}/*&output=json&fl=original&collapse=urlkey"
COMMONCRAWL_API = "https://index.commoncrawl.org/CC-MAIN-2024-18-index?url={}&output=json&fl=url"


def wayback_urls(engine):
    engine._log("INFO", "Fetching URLs from Wayback Machine...")
    parsed = urlparse(engine.target_url)
    domain = parsed.netloc or parsed.path
    urls = set()

    try:
        resp = requests.get(WAYBACK_API.format(domain), timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data[1:]:
                if entry and len(entry) > 0:
                    urls.add(entry[0])
            engine._log("FOUND", f"Wayback: {len(urls)} unique URLs discovered")
    except Exception as e:
        engine._log("WARN", f"Wayback query failed: {e}")

    return urls


def commoncrawl_urls(engine):
    engine._log("INFO", "Fetching URLs from Common Crawl...")
    parsed = urlparse(engine.target_url)
    domain = parsed.netloc or parsed.path
    urls = set()

    try:
        resp = requests.get(COMMONCRAWL_API.format(domain), timeout=15)
        if resp.status_code == 200:
            for line in resp.text.strip().split("\n"):
                try:
                    entry = json.loads(line)
                    if "url" in entry:
                        urls.add(entry["url"])
                except json.JSONDecodeError:
                    if line.strip():
                        urls.add(line.strip())
            engine._log("FOUND", f"CommonCrawl: {len(urls)} unique URLs discovered")
    except Exception as e:
        engine._log("WARN", f"CommonCrawl query failed: {e}")

    return urls


def passive_recon(engine):
    engine._log("INFO", "=== Passive Reconnaissance Phase ===")
    all_urls = set()

    wb = wayback_urls(engine)
    all_urls.update(wb)

    cc = commoncrawl_urls(engine)
    all_urls.update(cc)

    if all_urls:
        engine._log("FOUND", f"Total unique URLs from passive recon: {len(all_urls)}")
        parsed = urlparse(engine.target_url)
        base_domain = parsed.netloc or parsed.path

        paths = set()
        for u in sorted(all_urls):
            up = urlparse(u)
            path = up.path
            if path and path != "/":
                paths.add(path)
            if up.query:
                for qp in up.query.split("&"):
                    if "=" in qp:
                        key = qp.split("=")[0]
                        paths.add(f"{up.path}?{key}=TEST")

        interesting = [p for p in sorted(paths) if any(
            ext in p.lower() for ext in [
                ".php", ".asp", ".aspx", ".jsp", ".do", ".action",
                ".json", ".xml", ".wsdl", ".config", ".env",
                ".git", ".svn", ".bak", ".old", ".swp",
                "api", "admin", "backup", "dev", "test", "debug",
                "upload", "download", "ws", "graphql",
            ]
        )]

        if interesting:
            engine._log("FOUND", f"Interesting paths from passive recon ({len(interesting)}):")
            for p in interesting[:30]:
                engine._log("FOUND", f"  {p}")
                engine.results.setdefault("recon_urls", []).append(p)

    engine.results["recon"] = {
        "total_urls": len(all_urls),
        "interesting_paths": list(all_urls)[:50],
    }
    engine._log("INFO", "Passive recon complete.")
    return list(all_urls)
