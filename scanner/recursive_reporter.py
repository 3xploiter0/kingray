import json
import os


def generate_recursive_json_report(results, output_path="kingray_recursive_report.json"):
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    return output_path


def generate_recursive_html_report(results, output_path="kingray_recursive_report.html"):
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>KingRay Recursive Scan Report - {results.get('target', 'Unknown')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #0f0f1a; color: #e0e0e0; padding: 2rem; }}
        h1 {{ color: #ff6b35; margin-bottom: 0.5rem; }}
        h2 {{ color: #ff9f43; margin: 1.5rem 0 0.5rem; border-bottom: 1px solid #2a2a3e; padding-bottom: 0.3rem; }}
        h3 {{ color: #ffcc00; margin: 1rem 0 0.5rem; }}
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
        .url-cell {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .tech-tag {{ display: inline-block; background: #2a2a3e; padding: 0.2rem 0.5rem; border-radius: 4px; margin: 0.1rem; font-size: 0.8rem; }}
    </style>
</head>
<body>
    <h1>KingRay Recursive Vulnerability Scan Report</h1>
    <div class="meta">
        <strong>Target:</strong> {results.get('target', 'Unknown')}<br>
        <strong>Started:</strong> {results.get('scan_start', 'N/A')}<br>
        <strong>Ended:</strong> {results.get('scan_end', 'N/A')}
    </div>

    <div class="summary">
        <div class="stat-box"><span class="" style="color:#ff4757">{len(results.get('vulnerabilities', []))}</span><span class="label">Vulnerabilities</span></div>
        <div class="stat-box"><span style="color:#2ed573">{len(results.get('discovered_urls', []))}</span><span class="label">URLs Discovered</span></div>
        <div class="stat-box"><span style="color:#ff9f43">{len(results.get('forms_found', []))}</span><span class="label">Forms Found</span></div>
        <div class="stat-box"><span style="color:#3742fa">{len(results.get('targets_scanned', []))}</span><span class="label">Pages Scanned</span></div>
    </div>

    <div class="nav">
        <a href="#urls">Discovered URLs</a>
        <a href="#vulns">Vulnerabilities</a>
        <a href="#forms">Forms</a>
        <a href="#tech">Technology Stack</a>
        <a href="#scan">Scan Details</a>
    </div>

    <h2 id="urls">Discovered URLs</h2>
    <table>
        <tr><th>URL</th><th>Depth</th><th>Status</th><th>Size</th><th>Forms</th><th>Parameters</th></tr>
"""
    
    for target in results.get('targets_scanned', []):
        url = target.get('url', '')
        depth = target.get('depth', 0)
        status = target.get('status_code', 0)
        size = target.get('content_length', 0)
        forms = target.get('forms_found', 0)
        params = len(target.get('parameters_found', []))
        
        status_badge = "badge-success" if status == 200 else "badge-warning" if status in (301, 302) else "badge-danger"
        
        html += f"""        <tr>
            <td class="url-cell" title="{url}">{url}</td>
            <td>{depth}</td>
            <td><span class="badge {status_badge}">{status}</span></td>
            <td>{size}</td>
            <td>{forms}</td>
            <td>{params}</td>
        </tr>
"""
    
    html += """    </table>

    <h2 id="vulns">Vulnerabilities Found</h2>
"""
    
    if results.get('vulnerabilities'):
        html += """    <table>
        <tr><th>Type</th><th>URL</th><th>Parameter</th><th>Payload</th><th>Evidence</th></tr>
"""
        for vuln in results.get('vulnerabilities', []):
            vuln_type = vuln.get('type', '')
            url = vuln.get('url', '')
            details = vuln.get('details', {})
            param = details.get('parameter', '')
            payload = details.get('payload', '')
            evidence = ', '.join(details.get('evidence', [])) if isinstance(details.get('evidence'), list) else str(details.get('evidence', ''))
            
            html += f"""        <tr>
            <td><span class="badge badge-danger">{vuln_type}</span></td>
            <td class="url-cell" title="{url}">{url}</td>
            <td>{param}</td>
            <td><code>{payload[:50]}{'...' if len(payload) > 50 else ''}</code></td>
            <td>{evidence[:100]}{'...' if len(evidence) > 100 else ''}</td>
        </tr>
"""
        html += """    </table>
"""
    else:
        html += """    <p>No vulnerabilities found.</p>
"""
    
    html += """    <h2 id="forms">Forms Discovered</h2>
"""
    
    if results.get('forms_found'):
        html += """    <table>
        <tr><th>URL</th><th>Action</th><th>Method</th><th>Inputs</th></tr>
"""
        for form in results.get('forms_found', []):
            url = form.get('url', '')
            action = form.get('action', '')
            method = form.get('method', 'GET')
            inputs = form.get('inputs', [])
            input_names = ', '.join([inp.get('name', '') for inp in inputs[:3]])
            if len(inputs) > 3:
                input_names += f" (+{len(inputs) - 3} more)"
            
            html += f"""        <tr>
            <td class="url-cell" title="{url}">{url}</td>
            <td>{action}</td>
            <td><span class="badge badge-info">{method}</span></td>
            <td>{input_names}</td>
        </tr>
"""
        html += """    </table>
"""
    else:
        html += """    <p>No forms found.</p>
"""
    
    html += """    <h2 id="tech">Technology Stack by URL</h2>
"""
    
    if results.get('tech_stack_by_url'):
        html += """    <table>
        <tr><th>URL</th><th>Technologies</th><th>Aggressive Mode</th></tr>
"""
        for url, tech_info in results.get('tech_stack_by_url', {}).items():
            technologies = tech_info.get('technologies', [])
            aggressive = tech_info.get('aggressive_mode', {})
            tech_tags = ' '.join([f'<span class="tech-tag">{tech}</span>' for tech in technologies[:5]])
            if len(technologies) > 5:
                tech_tags += f' <span class="tech-tag">+{len(technologies) - 5} more</span>'
            
            aggressive_str = ', '.join([f"{k}: {v}" for k, v in aggressive.items()][:3])
            
            html += f"""        <tr>
            <td class="url-cell" title="{url}">{url}</td>
            <td>{tech_tags}</td>
            <td>{aggressive_str}</td>
        </tr>
"""
        html += """    </table>
"""
    else:
        html += """    <p>No technology information available.</p>
"""
    
    html += """    <h2 id="scan">Scan Details</h2>
    <pre style="background: #1a1a2e; padding: 1rem; border-radius: 8px; overflow: auto;">
"""
    
    import json
    html += json.dumps(results, indent=2)
    
    html += """    </pre>
</body>
</html>"""
    
    with open(output_path, "w") as f:
        f.write(html)
    return output_path