# 🦅 KingRay v4.0 - Professional Web Vulnerability Scanner

**KingRay** is a professional-grade, recursive web vulnerability scanner built for red teaming operations. It implements comprehensive OWASP Top 10 detection with zero false positives through differential analysis.

## 🚀 Features

### **Core Scanning Engine**
- **Recursive Scanning**: Automatically discovers and scans new paths (`/login`, `/admin`, etc.)
- **Form Extraction**: Parses HTML to find `<form>` tags and `<input>` fields for parameter testing
- **Differential Analysis**: Compares attack responses against baselines to eliminate false positives
- **Multi-threaded**: Concurrent scanning for maximum speed
- **Smart Parameter Context**: Detects GET query params, POST form fields, and JSON bodies

### **OWASP Top 10 Coverage**
1. **SQL Injection (SQLi)**
   - Error-based, boolean-based, time-based detection
   - Auth bypass detection via redirect analysis (302 → `/dashboard`, `/admin`)
   - Session cookie analysis (new `Set-Cookie` after injection)
   - WAF detection with bypass suggestions
   - Status code change analysis (200→500, 200→404)

2. **Cross-Site Scripting (XSS)**
   - Polyglot payloads with unique confirmation tags
   - Context detection (script, href, html)
   - Differential reflection analysis

3. **Broken Authentication**
   - Default credential testing (`admin:admin`, `root:root`, etc.)
   - SQLi-driven auth bypass detection
   - JWT security analysis (none algorithm, missing expiration)
   - Weak cookie flag detection

4. **Security Misconfiguration**
   - Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
   - Server header information leakage
   - HTTP vs HTTPS detection

5. **Sensitive Data Exposure**
   - Cryptographic failures detection
   - Plain HTTP traffic detection

6. **Additional Vulnerabilities**
   - **Command Injection (CMDI)**: Unique tag injection with smart timing thresholds
   - **Server-Side Template Injection (SSTI)**: Math verification (`{{1337*2}}` → `2674`)
   - **Local File Inclusion (LFI)**: Concurrent testing with baseline comparison
   - **Server-Side Request Forgery (SSRF)**: Cloud metadata + internal IP probes
   - **XML External Entity (XXE)**: File read payloads with indicator matching
   - **Insecure Direct Object Reference (IDOR)**: Response diffing with 10% size threshold

### **Intelligence Features**
- **Heuristic Engine**: Technology stack detection (Python/Flask, PHP, Django, Laravel, WordPress, etc.)
- **Aggressive Mode**: Framework-specific payloads when tech is detected
- **Passive Recon**: Wayback Machine + Common Crawl API queries
- **Recursive Discovery**: Directory busting on each discovered page
- **Link Extraction**: Follows `<a href>` tags for comprehensive coverage

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/kingray.git
cd kingray

# Install dependencies
pip install -r requirements.txt
```

## 🎯 Usage

### **Standard Scan (Single URL)**
```bash
python kingray.py -u http://target.com
```

### **Recursive Scan (Discover & Scan All Pages)**
```bash
python kingray_recursive.py -u http://target.com --max-depth 2 --max-urls 50
```

### **Advanced Options**
```bash
# Custom threads and timeout
python kingray.py -u http://target.com --threads 20 --timeout 10

# Skip specific modules
python kingray.py -u http://target.com --no-recon --no-heuristic --no-dirbust

# Generate HTML report
python kingray.py -u http://target.com --html -o my_report

# Recursive scan with limits
python kingray_recursive.py -u http://target.com \
  --max-depth 3 \
  --max-urls 100 \
  --threads 15 \
  --timeout 5 \
  --html
```

## 📊 Command Line Options

### **Common Options**
| Flag | Description | Default |
|------|-------------|---------|
| `-u`, `--url` | Target URL (required) | - |
| `-t`, `--threads` | Concurrent threads | 10 |
| `--timeout` | HTTP request timeout (seconds) | 5 |
| `-o`, `--output` | Report filename (no extension) | `kingray_report` |
| `--user-agent` | Custom User-Agent string | `KingRay-Scanner/4.0` |
| `--html` | Generate HTML report | False |

### **Module Toggles (kingray.py)**
| Flag | Description |
|------|-------------|
| `--no-recon` | Skip passive recon (Wayback/CommonCrawl) |
| `--no-heuristic` | Skip heuristic tech detection |
| `--no-dirbust` | Skip directory busting |
| `--no-sqli` | Skip SQL injection |
| `--no-xss` | Skip XSS |
| `--no-idor` | Skip IDOR |
| `--no-cmdi` | Skip command injection |
| `--no-crypto` | Skip crypto/TLS checks |
| `--no-misconfig` | Skip misconfiguration checks |
| `--no-auth` | Skip authentication checks |
| `--no-ssrf` | Skip SSRF checks |
| `--no-xxe` | Skip XXE checks |
| `--no-lfi` | Skip LFI checks |
| `--no-ssti` | Skip SSTI checks |

### **Recursive Scan Options (kingray_recursive.py)**
| Flag | Description | Default |
|------|-------------|---------|
| `--max-depth` | Maximum recursion depth | 3 |
| `--max-urls` | Maximum URLs to scan | 100 |

## 📁 Project Structure

```
kingray/
├── kingray.py              # Standard CLI entry point (single URL)
├── kingray_recursive.py    # Recursive CLI entry point
├── run.py                  # Alternative runner
├── requirements.txt        # Dependencies
├── README.md               # This file
└── scanner/
    ├── engine.py           # Core scanner engine v4.0
    ├── recursive_engine.py # Recursive scanning engine
    ├── reporter.py         # JSON/HTML report generator
    ├── recursive_reporter.py # Recursive scan reporter
    └── modules/
        ├── dirbust.py      # Directory busting
        ├── sqli.py         # SQL injection (with auth bypass, WAF, status code analysis)
        ├── xss.py          # XSS detection
        ├── idor.py         # IDOR detection
        ├── cmdi.py         # Command injection
        ├── crypto.py       # Cryptographic failures
        ├── misconfig.py    # Security misconfiguration
        ├── auth.py         # Authentication issues (with SQLi-driven bypass)
        ├── ssrf.py         # SSRF detection
        ├── xxe.py          # XXE detection
        ├── lfi.py          # LFI detection
        ├── ssti.py         # SSTI detection
        ├── recon.py        # Passive reconnaissance
        ├── heuristic.py    # Heuristic tech detection
        └── wordlists/      # Directory busting wordlists
```

## 🔬 Technical Highlights

### **Zero False Positives**
- All findings use **differential analysis** (baseline vs attack comparison)
- Injection modules use **unique randomized strings** (`KR_XSS_CONFIRMED`, `KR_CMDI_XXXX`)
- Timing-based detections use **smart thresholds** (`T_attack > T_base + 5.0s`)

### **Professional Detection Logic**
- **Redirect Intelligence**: If injection causes 302 redirect to `/dashboard`/`/admin` — flag as **Critical: Auth Bypass via SQLi**
- **Session Cookie Analysis**: If `Set-Cookie` header has new session token after injection — mark as confirmed exploit
- **Time-Based Double-Verification**: Auto-retry with `SLEEP(2)` after `SLEEP(5)` to confirm
- **WAF Detection**: If 403/406 received only when sending payloads (not baseline) — log WAF detected
- **Status Code Analysis**: Detect 200→500 (error-based SQLi) and 200→404 (boolean-based SQLi)

### **Recursive Scanning**
- **ScanQueue System**: Manages discovered URLs with depth limits
- **Form Extraction**: Uses BeautifulSoup to parse HTML forms and inputs
- **Link Following**: Extracts `<a href>` tags for comprehensive discovery
- **Heuristic per Path**: Technology detection runs on each discovered page

## 📈 Sample Output

```
   ╔══════════════════════════════════════╗
   ║          KINGRAY v4.0                ║
   ║    OWASP Top 10 Scanner              ║
   ║    Recursive Red Team Edition        ║
   ╚══════════════════════════════════════╝
    
  Target     : http://target.com
  Threads    : 10
  Timeout    : 5s
--------------------------------------------------
[INFO] Starting SQLi detection on http://target.com/login
[INFO] Baseline for 'username': 0.64s, status=200
[VULN] CRITICAL: SQLi Auth Bypass on 'username' via or_true_dash
[VULN]   Injection caused redirect to /dashboard (baseline was not a redirect)
[INFO] SQLi detection complete. Confirmed: 1.
[VULN] XSS confirmed in 'search' via iframe_srcdoc (html context)
[VULN] Site is served over HTTP (no encryption)
[WARN] Missing security header: HTTP Strict Transport Security (HSTS)
```

## 📄 Reports

### **JSON Report**
```json
{
  "target": "http://target.com",
  "scan_start": "2026-04-22T10:30:00",
  "sqli": [
    {
      "parameter": "username",
      "payload": "' OR '1'='1' --",
      "evidence": ["redirect auth bypass: /dashboard"],
      "auth_bypass": {
        "type": "auth_bypass_redirect",
        "location": "/dashboard",
        "detail": "Injection (or_true_dash) caused redirect to /dashboard"
      },
      "status": 302,
      "severity": "critical"
    }
  ],
  "xss": [...],
  "misconfig": [...]
}
```

### **HTML Report**
- Interactive navigation between vulnerability types
- Severity badges (critical, high, medium, low)
- Statistics dashboard
- Full scan details

## 🛡️ Professional Use Cases

### **Red Team Operations**
- Comprehensive attack surface mapping
- Auth bypass discovery for privilege escalation
- Session manipulation detection
- WAF fingerprinting and bypass research

### **Bug Bounty Hunting**
- Recursive discovery of hidden endpoints
- Automated vulnerability confirmation
- Professional-grade reporting for submissions
- Differential analysis to avoid false positives

### **Security Audits**
- OWASP Top 10 compliance checking
- Security header validation
- Technology stack analysis
- Configuration review

## ⚠️ Disclaimer

**This tool is for authorized security testing and educational purposes only.**

- Only test systems you own or have explicit written permission to test
- Compliance with applicable laws is your responsibility
- The authors assume no liability for misuse of this software

## 📝 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

**KingRay v4.0** - Professional web vulnerability scanning for the modern red teamer. 🦅