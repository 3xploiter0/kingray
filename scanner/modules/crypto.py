import ssl
import socket
from urllib.parse import urlparse


WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "anon",
    "PSK", "SRP",
]

WEAK_TLS_VERSIONS = {
    "TLSv1.0": "TLS 1.0 (deprecated, PCI DSS non-compliant)",
    "TLSv1.1": "TLS 1.1 (deprecated)",
    "SSLv3": "SSL 3.0 (POODLE vulnerability)",
    "SSLv2": "SSL 2.0 (broken)",
}


def crypto_check(engine):
    engine._log("INFO", f"Starting cryptographic security checks on {engine.target_url}")
    results = []

    parsed = urlparse(engine.target_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        engine._log("VULN", "Site is served over HTTP (no encryption)")
        results.append({
            "check": "http_instead_of_https",
            "detail": "Site is accessible over plain HTTP. All traffic is unencrypted.",
            "severity": "high",
        })

    if parsed.scheme == "https" or port == 443:
        for version_name, desc in WEAK_TLS_VERSIONS.items():
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                if version_name == "SSLv2":
                    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
                elif version_name == "SSLv3":
                    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
                elif version_name == "TLSv1.0":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1
                    ctx.maximum_version = ssl.TLSVersion.TLSv1
                elif version_name == "TLSv1.1":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_1

                with socket.create_connection((hostname, port), timeout=engine.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        engine._log("VULN", f"Weak TLS version: {version_name} - {desc}")
                        cipher = ssock.cipher()
                        results.append({
                            "check": "weak_tls_version",
                            "detail": f"{version_name} supported - {desc}",
                            "cipher": cipher[0] if cipher else "unknown",
                            "severity": "high",
                        })
            except Exception:
                pass

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=engine.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        weak = [w for w in WEAK_CIPHERS if w.lower() in cipher_name.lower()]
                        if weak:
                            engine._log("VULN", f"Weak cipher in use: {cipher_name}")
                            results.append({
                                "check": "weak_cipher",
                                "detail": f"Negotiated weak cipher: {cipher_name}",
                                "severity": "medium",
                            })
        except Exception:
            pass

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=engine.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        from datetime import datetime
                        expires = cert.get("notAfter", "")
                        if expires:
                            try:
                                expiry_date = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
                                if expiry_date < datetime.now():
                                    engine._log("VULN", f"SSL certificate expired: {expires}")
                                    results.append({
                                        "check": "expired_certificate",
                                        "detail": f"SSL certificate expired on {expires}",
                                        "severity": "high",
                                    })
                            except ValueError:
                                pass
        except Exception:
            pass

    try:
        resp = engine.request("", method="GET")
        if resp and resp.headers:
            ct = resp.headers.get("Content-Type", "")
            if "text/html" in ct and "charset" not in ct:
                engine._log("WARN", "No charset specified in Content-Type (possible encoding issues)")
                results.append({
                    "check": "missing_charset",
                    "detail": "Content-Type header missing charset directive",
                    "severity": "low",
                })
    except Exception:
        pass

    engine.results["crypto"] = results
    engine._log("INFO", f"Crypto checks complete. Found {len(results)} issues.")
    return results
