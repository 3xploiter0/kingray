import re
from urllib.parse import urlparse, parse_qs, urlunparse

NUMERIC_PATTERN = re.compile(r"/(\d+)(?:\?|/|$)")
UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

IDOR_PROBES = [
    "1", "2", "3", "100", "9999", "-1", "0",
    "admin", "000001",
]

COMMON_IDOR_PARAMS = [
    "id", "user_id", "userId", "uid", "account_id", "accountId",
    "customer_id", "customerId", "profile_id", "profileId",
    "order_id", "orderId", "invoice_id", "invoiceId", "document_id",
    "file_id", "fileId", "item_id", "itemId", "product_id",
    "productId", "ticket_id", "ticketId", "msg_id", "message_id",
    "post_id", "postId", "article_id", "articleId", "ref",
    "reference", "token", "key", "uuid",
]


def _extract_numeric_ids(url):
    ids = set()
    parsed = urlparse(url)
    path_matches = NUMERIC_PATTERN.findall(parsed.path)
    ids.update(path_matches)
    params = parse_qs(parsed.query)
    for param in COMMON_IDOR_PARAMS:
        if param in params:
            for val in params[param]:
                if val.isdigit():
                    ids.add(val)
    return list(ids) if ids else ["1"]


def _responses_differ(resp_a, resp_b):
    if resp_a is None or resp_b is None:
        return False
    if resp_a.status_code != resp_b.status_code:
        return True
    body_a = resp_a.text.strip()
    body_b = resp_b.text.strip()
    if not body_a or not body_b:
        return False
    diff = abs(len(body_a) - len(body_b))
    threshold = max(len(body_a), len(body_b)) * 0.15
    return diff > threshold


def idor_check(engine):
    engine._log("INFO", f"Starting IDOR detection on {engine.target_url}")
    results = []

    parsed = urlparse(engine.target_url)
    params = parse_qs(parsed.query)
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", ""))

    existing_ids = _extract_numeric_ids(engine.target_url)
    baseline_id = existing_ids[0]

    for param_name in params:
        baseline_resp = engine.request(base_url, params={k: v[0] for k, v in params.items()})
        if baseline_resp is None:
            continue

        for probe in IDOR_PROBES:
            if probe == params[param_name][0]:
                continue

            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = probe
            resp = engine.request(base_url, params=test_params)
            if resp is None:
                continue

            if _responses_differ(baseline_resp, resp):
                engine._log("VULN", f"IDOR in param '{param_name}' — probe '{probe}' differs from baseline "
                                    f"(status: {resp.status_code}, size: {len(resp.content)} vs {len(baseline_resp.content)})")
                results.append({
                    "type": "query_parameter",
                    "parameter": param_name,
                    "original_value": params[param_name][0],
                    "probe_value": probe,
                    "url": resp.url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "baseline_size": len(baseline_resp.content),
                })
                break

    for path_id in existing_ids:
        for probe in IDOR_PROBES:
            if probe == str(path_id):
                continue
            test_path = parsed.path.replace(str(path_id), probe)
            test_url = urlunparse((parsed.scheme, parsed.netloc, test_path, parsed.params, parsed.query, ""))
            baseline_path = parsed.path
            baseline_url = urlunparse((parsed.scheme, parsed.netloc, baseline_path, parsed.params, parsed.query, ""))

            resp = engine.request(test_url.lstrip(engine.target_url.rstrip("/")))
            baseline_resp = engine.request(baseline_url.lstrip(engine.target_url.rstrip("/")))

            if resp and baseline_resp and _responses_differ(baseline_resp, resp):
                engine._log("VULN", f"IDOR in URL path — changed '{path_id}' to '{probe}' "
                                    f"(status: {resp.status_code}, size: {len(resp.content)} vs {len(baseline_resp.content)})")
                results.append({
                    "type": "url_path",
                    "parameter": "path_id",
                    "original_value": str(path_id),
                    "probe_value": probe,
                    "url": test_url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "baseline_size": len(baseline_resp.content),
                })
                break

    if not results:
        engine._log("INFO", "No IDOR findings — all probes returned baseline-equivalent responses")
    engine.results["idor"] = results
    engine._log("INFO", f"IDOR detection complete. Confirmed: {len(results)}.")
    return results
