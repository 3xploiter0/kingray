import re
from urllib.parse import urlparse


TECH_SIGNATURES = [
    {
        "name": "PHP",
        "severity": "info",
        "checks": [
            {"type": "header", "header": "X-Powered-By", "pattern": r"PHP"},
            {"type": "header", "header": "Server", "pattern": r"PHP"},
            {"type": "cookie", "pattern": r"PHPSESSID"},
            {"type": "extension", "pattern": r"\.php"},
        ],
        "aggressive_lfi": True,
        "aggressive_cmdi": True,
    },
    {
        "name": "PHP 5.x",
        "severity": "critical",
        "checks": [
            {"type": "header", "header": "X-Powered-By", "pattern": r"PHP/5\."},
        ],
        "aggressive_lfi": True,
        "aggressive_cmdi": True,
        "aggressive_sqli": True,
    },
    {
        "name": "Django",
        "severity": "info",
        "checks": [
            {"type": "header", "header": "Server", "pattern": r"WSGIServer|gunicorn"},
            {"type": "cookie", "pattern": r"csrftoken|sessionid"},
            {"type": "header", "header": "X-Frame-Options", "pattern": r"SAMEORIGIN"},
        ],
        "wordlist": [
            "admin/", "api/", ".env", "settings.py", "urls.py",
            "wsgi.py", "manage.py", "db.sqlite3", "static/",
            "media/", "__debugbar__", "debug_toolbar/",
        ],
    },
    {
        "name": "Laravel",
        "severity": "info",
        "checks": [
            {"type": "cookie", "pattern": r"laravel_session|XSRF-TOKEN"},
            {"type": "header", "header": "Set-Cookie", "pattern": r"laravel"},
            {"type": "extension", "pattern": r"\.env"},
        ],
        "wordlist": [
            ".env", "storage/", "vendor/", "artisan", "routes/",
            "config/", "database/", "_debugbar/", "api/",
            "public/", "resources/",
        ],
    },
    {
        "name": "WordPress",
        "severity": "info",
        "checks": [
            {"type": "cookie", "pattern": r"wordpress_|wp-"},
            {"type": "header", "header": "X-Powered-By", "pattern": r"WordPress"},
            {"type": "body", "pattern": r"/wp-content/|/wp-includes/|/wp-json/"},
        ],
        "wordlist": [
            "wp-admin/", "wp-content/", "wp-includes/", "wp-json/",
            "wp-config.php", "wp-config.bak", ".htaccess",
            "xmlrpc.php", "wp-login.php", "wp-cron.php",
        ],
    },
    {
        "name": "ASP.NET",
        "severity": "info",
        "checks": [
            {"type": "header", "header": "X-Powered-By", "pattern": r"ASP\.NET"},
            {"type": "header", "header": "X-AspNet-Version", "pattern": r"."},
            {"type": "cookie", "pattern": r"ASP\.NET_SessionId|\.ASPXAUTH"},
            {"type": "extension", "pattern": r"\.aspx|\.asmx|\.ashx"},
        ],
        "aggressive_lfi": True,
    },
    {
        "name": "Express/Node.js",
        "severity": "info",
        "checks": [
            {"type": "header", "header": "X-Powered-By", "pattern": r"Express"},
            {"type": "header", "header": "Server", "pattern": r"Node"},
        ],
    },
    {
        "name": "Python/Flask",
        "severity": "info",
        "checks": [
            {"type": "header", "header": "Server", "pattern": r"Werkzeug|Python"},
            {"type": "cookie", "pattern": r"session"},
        ],
        "aggressive_ssti": True,
    },
    {
        "name": "Java/Spring",
        "severity": "info",
        "checks": [
            {"type": "header", "header": "X-Application-Context", "pattern": r"."},
            {"type": "cookie", "pattern": r"JSESSIONID"},
            {"type": "extension", "pattern": r"\.jsp|\.do|\.action"},
        ],
    },
    {
        "name": "Ruby/Rails",
        "severity": "info",
        "checks": [
            {"type": "header", "header": "X-Powered-By", "pattern": r"Phusion|Rails"},
            {"type": "cookie", "pattern": r"_session"},
            {"type": "header", "header": "Server", "pattern": r"WEBrick|Thin|Puma"},
        ],
    },
]


def _check_tech(engine, sig):
    resp = engine.request()
    if resp is None:
        return False

    headers = resp.headers
    body = resp.text
    cookies = dict(resp.cookies)
    set_cookie = headers.get("Set-Cookie", "")
    parsed = urlparse(engine.target_url)

    for check in sig["checks"]:
        if check["type"] == "header":
            val = headers.get(check["header"], "")
            if re.search(check["pattern"], val, re.IGNORECASE):
                return True
        elif check["type"] == "cookie":
            for name in cookies:
                if re.search(check["pattern"], name, re.IGNORECASE):
                    return True
            if re.search(check["pattern"], set_cookie, re.IGNORECASE):
                return True
        elif check["type"] == "body":
            if re.search(check["pattern"], body, re.IGNORECASE):
                return True
        elif check["type"] == "extension":
            if re.search(check["pattern"], parsed.path, re.IGNORECASE):
                return True
    return False


def heuristic_detect(engine):
    engine._log("INFO", "=== Heuristic Engine: Detecting Technology Stack ===")
    detected = []

    for sig in TECH_SIGNATURES:
        if _check_tech(engine, sig):
            detected.append(sig)
            engine._log("FOUND", f"Detected: {sig['name']} (severity: {sig['severity']})")

    engine.results["tech_stack"] = [t["name"] for t in detected]
    engine._log("INFO", f"Tech stack: {', '.join(t['name'] for t in detected) or 'Unknown'}")

    framework_wordlists = []
    aggressive = {"lfi": False, "cmdi": False, "sqli": False, "ssti": False}

    for t in detected:
        if t.get("wordlist"):
            framework_wordlists.extend(t["wordlist"])
        if t.get("aggressive_lfi"):
            aggressive["lfi"] = True
        if t.get("aggressive_cmdi"):
            aggressive["cmdi"] = True
        if t.get("aggressive_sqli"):
            aggressive["sqli"] = True
        if t.get("aggressive_ssti"):
            aggressive["ssti"] = True

    if any(t["severity"] == "critical" for t in detected):
        engine._log("VULN", "CRITICAL tech detected — enabling ALL aggressive modules")
        aggressive = {k: True for k in aggressive}

    if framework_wordlists:
        engine._log("FOUND", f"Framework-specific wordlist ({len(framework_wordlists)} paths)")
        engine.results["framework_wordlist"] = framework_wordlists

    engine.results["aggressive_mode"] = aggressive

    for mod, enabled in aggressive.items():
        if enabled:
            engine._log("INFO", f"  Aggressive mode enabled for: {mod.upper()}")

    engine._log("INFO", "Heuristic analysis complete.")
    return detected, aggressive, framework_wordlists
