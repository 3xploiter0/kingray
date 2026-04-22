from urllib.parse import urlparse


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "HTTP Strict Transport Security (HSTS)",
        "severity": "medium",
        "check": lambda v: "max-age" in v,
    },
    "Content-Security-Policy": {
        "desc": "Content Security Policy (CSP)",
        "severity": "medium",
        "check": lambda v: True,
    },
    "X-Content-Type-Options": {
        "desc": "X-Content-Type-Options (nosniff)",
        "severity": "low",
        "check": lambda v: v.lower() == "nosniff",
    },
    "X-Frame-Options": {
        "desc": "X-Frame-Options (clickjacking protection)",
        "severity": "medium",
        "check": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
    },
    "X-XSS-Protection": {
        "desc": "X-XSS-Protection header",
        "severity": "low",
        "check": lambda v: "1" in v,
    },
    "Referrer-Policy": {
        "desc": "Referrer-Policy header",
        "severity": "low",
        "check": lambda v: True,
    },
    "Permissions-Policy": {
        "desc": "Permissions-Policy header",
        "severity": "low",
        "check": lambda v: True,
    },
    "Set-Cookie": {
        "desc": "Secure/HttpOnly cookie flags",
        "severity": "medium",
        "check": lambda v: "secure" in v.lower() and "httponly" in v.lower(),
    },
}


def misconfig_check(engine):
    engine._log("INFO", f"Starting security misconfiguration checks on {engine.target_url}")
    results = []

    resp = engine.request("", method="GET")
    if not resp:
        engine._log("WARN", "Could not reach target for misconfiguration checks")
        return results

    headers = resp.headers

    for header, info in SECURITY_HEADERS.items():
        value = headers.get(header)
        if not value:
            engine._log("WARN", f"Missing security header: {info['desc']}")
            results.append({
                "check": "missing_security_header",
                "header": header,
                "detail": f"Missing {info['desc']} header",
                "severity": info["severity"],
                "current": None,
            })
        elif not info["check"](value):
            engine._log("WARN", f"Misconfigured header: {header} = {value}")
            results.append({
                "check": "misconfigured_header",
                "header": header,
                "detail": f"{info['desc']} is present but misconfigured",
                "severity": info["severity"],
                "current": value,
            })

    server = headers.get("Server", "")
    if server:
        engine._log("INFO", f"Server header: {server}")
        results.append({
            "check": "server_info_leak",
            "header": "Server",
            "detail": f"Server header leaks version info: {server}",
            "severity": "low",
            "current": server,
        })

    x_powered = headers.get("X-Powered-By", "")
    if x_powered:
        engine._log("WARN", f"X-Powered-By leaks technology: {x_powered}")
        results.append({
            "check": "technology_leak",
            "header": "X-Powered-By",
            "detail": f"Technology info leaked: {x_powered}",
            "severity": "low",
            "current": x_powered,
        })

    via = headers.get("Via", "")
    if via:
        results.append({
            "check": "proxy_info_leak",
            "header": "Via",
            "detail": f"Proxy info leaked: {via}",
            "severity": "low",
            "current": via,
        })

    allow = headers.get("Allow", "")
    if allow:
        methods = [m.strip() for m in allow.split(",")]
        dangerous = [m for m in methods if m.upper() in ("PUT", "DELETE", "PATCH", "TRACE", "OPTIONS")]
        if dangerous:
            engine._log("VULN", f"Dangerous HTTP methods allowed: {', '.join(dangerous)}")
            results.append({
                "check": "dangerous_http_methods",
                "header": "Allow",
                "detail": f"Dangerous HTTP methods enabled: {', '.join(dangerous)}",
                "severity": "medium",
                "current": allow,
            })

    if "Access-Control-Allow-Origin" in headers:
        origin = headers["Access-Control-Allow-Origin"]
        if origin == "*":
            engine._log("VULN", "CORS is wide open: Access-Control-Allow-Origin: *")
            results.append({
                "check": "cors_wildcard",
                "header": "Access-Control-Allow-Origin",
                "detail": "CORS allows any origin (*)",
                "severity": "medium",
                "current": origin,
            })

    if "Access-Control-Allow-Credentials" in headers and headers["Access-Control-Allow-Credentials"].lower() == "true":
        engine._log("VULN", "CORS allows credentials - potential data exposure")
        results.append({
            "check": "cors_credentials",
            "header": "Access-Control-Allow-Credentials",
            "detail": "CORS allows credentials without origin restriction",
            "severity": "high",
            "current": "true",
        })

    try:
        options_resp = engine.request("", method="OPTIONS")
        if options_resp and options_resp.status_code == 200:
            allow_h = options_resp.headers.get("Allow", "")
            if allow_h:
                methods = [m.strip() for m in allow_h.split(",")]
                dangerous = [m for m in methods if m.upper() in ("PUT", "DELETE", "PATCH", "TRACE")]
                if dangerous:
                    engine._log("VULN", f"OPTIONS reveals dangerous methods: {', '.join(dangerous)}")
                    results.append({
                        "check": "options_discovery",
                        "header": "Allow (OPTIONS)",
                        "detail": f"OPTIONS request reveals: {allow_h}",
                        "severity": "medium",
                        "current": allow_h,
                    })
    except Exception:
        pass

    for path in ["/server-status", "/server-info", "/phpinfo.php", "/info.php", "/test.php"]:
        pr = engine.request(path)
        if pr and pr.status_code == 200:
            engine._log("VULN", f"Sensitive file exposed: {path} ({len(pr.content)} bytes)")
            results.append({
                "check": "sensitive_file_exposed",
                "path": path,
                "detail": f"Sensitive path returned 200: {path}",
                "severity": "high",
            })

    engine.results["misconfig"] = results
    engine._log("INFO", f"Misconfiguration checks complete. Found {len(results)} issues.")
    return results
