import time

CMDI_PAYLOADS = [
    {"name": "semicolon_echo", "payload": "; echo {}"},
    {"name": "pipe_echo", "payload": "| echo {}"},
    {"name": "backtick_echo", "payload": "`echo {}`"},
    {"name": "subshell_echo", "payload": "$(echo {})"},
    {"name": "semicolon_whoami", "payload": "; echo {}"},
    {"name": "pipe_whoami", "payload": "| echo {}"},
    {"name": "semicolon_sleep", "payload": "; sleep 5"},
    {"name": "pipe_sleep", "payload": "| sleep 5"},
    {"name": "ampersand_sleep", "payload": "& sleep 5 &"},
    {"name": "or_sleep", "payload": "|| sleep 5"},
]


def cmdi_check(engine):
    engine._log("INFO", f"Starting Command Injection detection on {engine.target_url}")
    results = []

    params = engine.extract_params()
    if not params:
        engine._log("WARN", "No parameters found for command injection testing")
        return results

    tag = engine.unique_tag("KR_CMDI")

    for param in params:
        baseline_time, baseline_text = engine.get_baseline_time(param)
        if baseline_time is None:
            engine._log("WARN", f"Skipping '{param}' — baseline request failed")
            continue

        engine._log("INFO", f"Baseline for '{param}': {baseline_time:.2f}s")

        for payload_entry in CMDI_PAYLOADS:
            if "{}" in payload_entry["payload"]:
                attack_value = payload_entry["payload"].format(tag)
            else:
                attack_value = payload_entry["payload"]

            args = engine.build_request_args(param, attack_value)
            start = time.time()
            resp = engine.request(**args)
            elapsed = time.time() - start

            if resp is None:
                continue

            resp_text = resp.text

            confirmed = False
            evidence = []

            if tag in resp_text:
                if not baseline_text or tag not in baseline_text:
                    confirmed = True
                    evidence.append(f"unique_tag '{tag}' reflected in response (not in baseline)")

            if "sleep" in payload_entry["name"]:
                if elapsed > baseline_time + 5.0:
                    confirmed = True
                    evidence.append(f"timing anomaly: baseline={baseline_time:.2f}s, attack={elapsed:.2f}s (+{elapsed - baseline_time:.2f}s)")

            if confirmed:
                engine._log("VULN", f"CMDI confirmed in '{param}' via {payload_entry['name']}")
                for e in evidence:
                    engine._log("VULN", f"  {e}")
                results.append({
                    "parameter": param,
                    "payload_type": payload_entry["name"],
                    "payload": attack_value,
                    "evidence": evidence,
                    "baseline_time": round(baseline_time, 2),
                    "attack_time": round(elapsed, 2),
                    "status": resp.status_code,
                })
                break

    engine.results["cmdi"] = results
    engine._log("INFO", f"Command injection complete. Confirmed: {len(results)}.")
    return results
