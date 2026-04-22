import os

WORDLISTS_DIR = os.path.join(os.path.dirname(__file__), "..", "wordlists")


def get_default_wordlist():
    wordlist_path = os.path.join(WORDLISTS_DIR, "common.txt")
    if os.path.exists(wordlist_path):
        with open(wordlist_path) as f:
            return [line.strip() for line in f if line.strip()]
    return [
        "admin", "login", "wp-admin", "admin.php", "administrator",
        "backup", "config", "css", "dashboard", "db",
        "images", "img", "includes", "index.php", "js",
        "lib", "login.php", "logout", "panel", "phpinfo.php",
        "private", "robots.txt", "sitemap.xml", "sql", "sqlite",
        "src", "status", "test", "tmp", "upload", "uploads",
        "vendor", "wp-content", "wp-includes", ".git/HEAD", ".env",
        "api", "api/v1", "graphql", "swagger.json", "api-docs",
    ]


def dirbust(engine):
    engine._log("INFO", f"Starting directory busting on {engine.target_url}")
    paths = get_default_wordlist()

    def check_path(path):
        resp = engine.request(path)
        if resp and resp.status_code in (200, 201, 204, 301, 302, 403):
            size = len(resp.content)
            return {
                "url": resp.url,
                "status": resp.status_code,
                "size": size,
                "path": path,
            }
        return None

    results = engine.run_concurrent(paths, check_path)
    for r in sorted(results, key=lambda x: x["path"]):
        engine._log("FOUND", f"{r['status']}  {r['url']}  ({r['size']} bytes)")
        engine.results["directories"].append(r)
    engine._log("INFO", f"Directory busting complete. Found {len(results)} paths.")
    return results
