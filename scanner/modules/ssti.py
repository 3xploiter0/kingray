from concurrent.futures import ThreadPoolExecutor, as_completed

SSTI_PAYLOADS = [
    {"engine": "jinja2_twig_nunjucks", "payload": "{{1337*2}}", "expected": "2674"},
    {"engine": "freemarker_velocity", "payload": "${1337*2}", "expected": "2674"},
    {"engine": "smarty", "payload": "{1337*2}", "expected": "2674"},
    {"engine": "jinja2_config", "payload": "{{config}}"},
    {"engine": "smarty_version", "payload": "{$smarty.version}"},
    {"engine": "jade_math", "payload": "= 1337*2", "expected": "2674"},
    {"engine": "velocity_math", "payload": "#set($x=1337*2)$x", "expected": "2674"},
]


def ssti_check(engine):
    engine._log("INFO", f"Starting SSTI detection on {engine.target_url}")
    results = []

    params = engine.extract_params()
    if not params:
        engine._log("WARN", "No parameters found for SSTI testing")
        return results

    def test_param(param):
        baseline_text = engine.get_baseline_text(param)
        if baseline_text is None:
            return None

        for entry in SSTI_PAYLOADS:
            args = engine.build_request_args(param, entry["payload"])
            resp = engine.request(**args)
            if resp is None:
                continue

            resp_text = resp.text
            confirmed = False
            evidence = []

            if "expected" in entry:
                if entry["expected"] in resp_text:
                    if not baseline_text or entry["expected"] not in baseline_text:
                        confirmed = True
                        evidence.append(f"math result '{entry['expected']}' in response (not in baseline)")

            if not confirmed and entry["payload"] in resp_text:
                if not baseline_text or entry["payload"] not in baseline_text:
                    confirmed = True
                    evidence.append(f"raw payload reflected in response (not in baseline)")

            if confirmed:
                engine._log("VULN", f"SSTI ({entry['engine']}) confirmed in '{param}'")
                for e in evidence:
                    engine._log("VULN", f"  {e}")
                return {
                    "parameter": param,
                    "engine": entry["engine"],
                    "payload": entry["payload"],
                    "evidence": evidence,
                }
        return None

    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(test_param, p): p for p in params}
        for future in as_completed(futures):
            try:
                r = future.result(timeout=30)
                if r:
                    results.append(r)
            except Exception:
                pass

    engine.results["ssti"] = results
    engine._log("INFO", f"SSTI detection complete. Confirmed: {len(results)}.")
    return results
