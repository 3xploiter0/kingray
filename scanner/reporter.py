import json
import os


def generate_json_report(results, output_path="report.json"):
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return output_path


def _section_table(title, columns, rows, col_attrs):
    html = f"""    <h2>{title}</h2>
    <table>
        <tr>"""
    for col in columns:
        html += f"<th>{col}</th>"
    html += "</tr>\n"
    for row in rows:
        html += "        <tr>"
        for i, attr in enumerate(col_attrs):
            val = row.get(attr, "")
            css = ""
            if attr == "severity":
                if val == "critical":
                    css = " class='badge badge-critical'"
                elif val == "high":
                    css = " class='badge badge-danger'"
                elif val == "medium":
                    css = " class='badge badge-warning'"
                elif val == "low":
                    css = " class='badge badge-info'"
                html += f"<td><span{css}>{val}</span></td>"
            else:
                html += f"<td>{val}</td>"
        html += "</tr>\n"
    html += "    </table>\n"
    return html


def generate_html_report(results, output_path="report.html"):
    vuln_count = 0
    for key in ["sqli", "xss", "idor", "cmdi", "ssrf", "xxe", "lfi", "ssti"]:
        vuln_count += len(results.get(key, []))
    misconfig_count = len(results.get("misconfig", []))
    auth_count = len(results.get("auth", []))
    crypto_count = len(results.get("crypto", []))
    dir_count = len(results.get("directories", []))

    all_count = sum(len(v) for k, v in results.items() if isinstance(v, list))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>KingRay Scan Report - {results['target']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #0f0f1a; color: #e0e0e0; padding: 2rem; }}
        h1 {{ color: #ff6b35; margin-bottom: 0.5rem; }}
        h2 {{ color: #ff9f43; margin: 1.5rem 0 0.5rem; border-bottom: 1px solid #2a2a3e; padding-bottom: 0.3rem; }}
        .meta {{ color: #888; margin-bottom: 2rem; }}
        .stat-box {{ display: inline-block; padding: 1rem 1.5rem; margin: 0.5rem;
                     border-radius: 8px; background: #1a1a2e; min-width: 140px; text-align: center; }}
        .stat-box span {{ font-size: 2rem; font-weight: bold; display: block; }}
        .stat-box .label {{ font-size: 0.8rem; color: #888; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
        th, td {{ padding: 0.6rem 0.75rem; text-align: left; border-bottom: 1px solid #2a2a3e; font-size: 0.9rem; }}
        th {{ background: #1a1a2e; color: #ff9f43; position: sticky; top: 0; }}
        tr:hover {{ background: #1a1a2e; }}
        .badge {{ display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px;
                  font-size: 0.75rem; font-weight: bold; }}
        .badge-critical {{ background: #8b0000; color: #fff; }}
        .badge-danger {{ background: #ff4757; color: #fff; }}
        .badge-warning {{ background: #ffa502; color: #fff; }}
        .badge-success {{ background: #2ed573; color: #fff; }}
        .badge-info {{ background: #3742fa; color: #fff; }}
        .summary {{ display: flex; flex-wrap: wrap; margin-bottom: 1rem; }}
        .nav {{ margin: 1rem 0; padding: 0.5rem 0; border-bottom: 1px solid #2a2a3e; }}
        .nav a {{ color: #ff9f43; text-decoration: none; margin-right: 1.5rem; font-size: 0.9rem; }}
        .nav a:hover {{ color: #ff6b35; text-decoration: underline; }}
    </style>
</head>
<body>
    <h1>KingRay Vulnerability Scanner Report</h1>
    <div class="meta">
        <strong>Target:</strong> {results['target']}<br>
        <strong>Started:</strong> {results.get('scan_start', 'N/A')}<br>
        <strong>Ended:</strong> {results.get('scan_end', 'N/A')}
    </div>

    <div class="summary">
        <div class="stat-box"><span class="" style="color:#ff4757">{vuln_count}</span><span class="label">Vulnerabilities</span></div>
        <div class="stat-box"><span style="color:#ffa502">{misconfig_count + auth_count + crypto_count}</span><span class="label">Config Issues</span></div>
        <div class="stat-box"><span style="color:#2ed573">{dir_count}</span><span class="label">Directories</span></div>
        <div class="stat-box"><span style="color:#ff9f43">{all_count}</span><span class="label">Total Findings</span></div>
    </div>

    <div class="nav">
        <a href="#dirbust">Directory Busting</a>
        <a href="#sqli">SQL Injection</a>
        <a href="#xss">XSS</a>
        <a href="#idor">IDOR</a>
        <a href="#cmdi">Command Injection</a>
        <a href="#lfi">LFI</a>
        <a href="#ssti">SSTI</a>
        <a href="#ssrf">SSRF</a>
        <a href="#xxe">XXE</a>
        <a href="#crypto">Crypto</a>
        <a href="#misconfig">Misconfig</a>
        <a href="#auth">Authentication</a>
    </div>
"""

    html += '<h2 id="dirbust">Discovered Directories</h2>\n<table><tr><th>Status</th><th>URL</th><th>Size</th></tr>\n'
    for d in results.get("directories", []):
        html += f"<tr><td><span class='badge badge-warning'>{d['status']}</span></td><td>{d['url']}</td><td>{d['size']}</td></tr>\n"
    html += "</table>\n"

    html += '<h2 id="sqli">SQL Injection</h2>\n<table><tr><th>Parameter</th><th>Payload</th><th>Evidence</th><th>WAF</th><th>Auth Bypass</th><th>Status Change</th><th>Status</th></tr>\n'
    for s in results.get("sqli", []):
        evidence = ", ".join(s.get("evidence", []))
        waf = ""
        if "waf" in s:
            waf = f"WAF ({s['waf'].get('status', '')})"
        auth_bypass = ""
        if "auth_bypass" in s:
            auth_bypass = f"Redirect: {s['auth_bypass'].get('location', '')}"
        elif "session_cookie" in s:
            auth_bypass = "Session cookie"
        status_change = ""
        if "status_change" in s:
            sc = s["status_change"]
            status_change = f"{sc.get('baseline', '')}→{sc.get('injection', '')}"
        html += f"<tr><td>{s['parameter']}</td><td>{s['payload']}</td><td>{evidence}</td><td>{waf}</td><td>{auth_bypass}</td><td>{status_change}</td><td><span class='badge badge-danger'>{s['status']}</span></td></tr>\n"
    html += "</table>\n"

    html += '<h2 id="xss">Cross-Site Scripting (XSS)</h2>\n<table><tr><th>Parameter</th><th>Payload</th><th>Status</th></tr>\n'
    for x in results.get("xss", []):
        html += f"<tr><td>{x['parameter']}</td><td>{x['payload']}</td><td><span class='badge badge-danger'>{x['status']}</span></td></tr>\n"
    html += "</table>\n"

    html += '<h2 id="idor">Insecure Direct Object Reference (IDOR)</h2>\n<table><tr><th>Type</th><th>Parameter</th><th>Original</th><th>Probe</th><th>Status</th><th>Size</th></tr>\n'
    for i in results.get("idor", []):
        badge = "badge-danger" if i['status'] == 200 else "badge-warning"
        html += f"<tr><td>{i['type']}</td><td>{i['parameter']}</td><td>{i['original_value']}</td><td>{i['probe_value']}</td><td><span class='badge {badge}'>{i['status']}</span></td><td>{i['size']}</td></tr>\n"
    html += "</table>\n"

    html += '<h2 id="cmdi">Command Injection</h2>\n<table><tr><th>Parameter</th><th>Payload</th><th>Indicators</th><th>Timing</th><th>Status</th></tr>\n'
    for c in results.get("cmdi", []):
        ind = ", ".join(c.get("indicators", []))
        html += f"<tr><td>{c['parameter']}</td><td>{c['payload']}</td><td>{ind}</td><td>{c.get('timing', '')}s</td><td><span class='badge badge-danger'>{c['status']}</span></td></tr>\n"
    html += "</table>\n"

    html += '<h2 id="lfi">Local File Inclusion (LFI)</h2>\n<table><tr><th>Parameter</th><th>Payload</th><th>Indicators</th><th>Status</th></tr>\n'
    for l in results.get("lfi", []):
        ind = ", ".join(l.get("indicators", []))
        html += f"<tr><td>{l['parameter']}</td><td>{l['payload']}</td><td>{ind}</td><td><span class='badge badge-danger'>{l['status']}</span></td></tr>\n"
    html += "</table>\n"

    html += '<h2 id="ssti">Server-Side Template Injection (SSTI)</h2>\n<table><tr><th>Parameter</th><th>Payload</th><th>Engine</th><th>Status</th></tr>\n'
    for s in results.get("ssti", []):
        html += f"<tr><td>{s['parameter']}</td><td>{s['payload']}</td><td>{s.get('engine', '')}</td><td><span class='badge badge-danger'>{s['status']}</span></td></tr>\n"
    html += "</table>\n"

    html += '<h2 id="ssrf">Server-Side Request Forgery (SSRF)</h2>\n<table><tr><th>Parameter</th><th>Payload</th><th>Indicators</th><th>Status</th></tr>\n'
    for s in results.get("ssrf", []):
        ind = ", ".join(s.get("indicators", []))
        html += f"<tr><td>{s['parameter']}</td><td>{s['payload']}</td><td>{ind}</td><td><span class='badge badge-danger'>{s['status']}</span></td></tr>\n"
    html += "</table>\n"

    html += '<h2 id="xxe">XML External Entity (XXE)</h2>\n<table><tr><th>Check</th><th>Detail</th><th>Severity</th></tr>\n'
    for x in results.get("xxe", []):
        html += f"<tr><td>{x.get('check', '')}</td><td>{x.get('detail', '')}</td><td><span class='badge badge-danger'>{x.get('severity', '')}</span></td></tr>\n"
    html += "</table>\n"

    html += '<h2 id="crypto">Cryptographic Failures</h2>\n<table><tr><th>Check</th><th>Detail</th><th>Severity</th></tr>\n'
    for c in results.get("crypto", []):
        sev = c.get("severity", "medium")
        badge = "badge-danger" if sev == "high" else "badge-warning" if sev == "medium" else "badge-info"
        html += f"<tr><td>{c.get('check', '')}</td><td>{c.get('detail', '')}</td><td><span class='badge {badge}'>{sev}</span></td></tr>\n"
    html += "</table>\n"

    html += '<h2 id="misconfig">Security Misconfiguration</h2>\n<table><tr><th>Check</th><th>Detail</th><th>Severity</th></tr>\n'
    for m in results.get("misconfig", []):
        sev = m.get("severity", "medium")
        badge = "badge-danger" if sev == "high" else "badge-warning" if sev == "medium" else "badge-info"
        html += f"<tr><td>{m.get('check', '')}</td><td>{m.get('detail', '')}</td><td><span class='badge {badge}'>{sev}</span></td></tr>\n"
    html += "</table>\n"

    html += '<h2 id="auth">Authentication Issues</h2>\n<table><tr><th>Check</th><th>Detail</th><th>Severity</th></tr>\n'
    for a in results.get("auth", []):
        sev = a.get("severity", "medium")
        badge = "badge-critical" if sev == "critical" else "badge-danger" if sev == "high" else "badge-warning" if sev == "medium" else "badge-info"
        html += f"<tr><td>{a.get('check', '')}</td><td>{a.get('detail', '')}</td><td><span class='badge {badge}'>{sev}</span></td></tr>\n"
    html += "</table>\n"

    html += """</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    return output_path
