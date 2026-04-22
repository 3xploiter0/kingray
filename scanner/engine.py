import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, parse_qs
import json
import time
import re
import uuid
from colorama import Fore, Style, init

init(autoreset=True)

FORM_INPUT_RE = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)


class Scanner:
    def __init__(self, target_url, threads=10, timeout=5, user_agent=None):
        self.target_url = target_url.rstrip("/")
        self.threads = threads
        self.timeout = timeout
        self.user_agent = user_agent or "KingRay-Scanner/3.0"
        self.session = self._create_session()  # Initialize session properly
        self.results = {
            "target": self.target_url,
            "tech_stack": [],
            "aggressive_mode": {},
            "recon": {},
            "recon_urls": [],
            "framework_wordlist": [],
            "directories": [],
            "sqli": [],
            "xss": [],
            "idor": [],
            "cmdi": [],
            "crypto": [],
            "misconfig": [],
            "auth": [],
            "ssrf": [],
            "xxe": [],
            "lfi": [],
            "ssti": [],
            "scan_start": None,
            "scan_end": None,
        }
        self._param_context = None
        self.aggressive = {}
        self.framework_wordlist = []
        self._baseline_cache = {}  # Cache baselines per parameter

    def _create_session(self):
        """Create a fresh session"""
        session = requests.Session()
        session.headers.update({
            "User-Agent": self.user_agent
        })
        return session

    def request(self, path="", method="GET", params=None, data=None, json_body=None, fresh_session=False):
        if path:
            url = urljoin(self.target_url.rstrip("/") + "/", path.lstrip("/"))
        else:
            url = self.target_url
        
        headers = {}
        
        try:
            # Use fresh session if requested (for baseline and independent requests)
            if fresh_session:
                session = self._create_session()
            else:
                session = self.session
            
            if json_body is not None:
                headers["Content-Type"] = "application/json"
                resp = session.post(url, json=json_body, timeout=self.timeout, allow_redirects=True)
            elif data is not None:
                resp = session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
            elif method == "GET":
                resp = session.get(url, params=params, timeout=self.timeout, allow_redirects=True)
            else:
                resp = session.post(url, params=params, data=data, timeout=self.timeout, allow_redirects=True)
            return resp
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.RequestException:
            return None

    def detect_param_context(self):
        if self._param_context:
            return self._param_context
        
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        if params:
            self._param_context = "GET"
            return "GET"

        # Use fresh session for detection
        resp = self.request(fresh_session=True)
        if resp:
            ct = resp.headers.get("Content-Type", "")
            if "json" in ct or "application/json" in ct:
                self._param_context = "JSON"
                return "JSON"

            form_fields = FORM_INPUT_RE.findall(resp.text)
            if form_fields:
                self._param_context = ("POST", form_fields)
                return ("POST", form_fields)

        self._param_context = "GET"
        return "GET"

    def extract_params(self):
        context = self.detect_param_context()
        if isinstance(context, tuple):
            return context[1]
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        return list(params.keys()) if params else []

    def build_request_args(self, param_name, attack_value):
        context = self.detect_param_context()
        if isinstance(context, tuple):
            return {"data": {param_name: attack_value}, "params": None, "json_body": None}
        if context == "JSON":
            return {"data": None, "params": None, "json_body": {param_name: attack_value}}
        return {"data": None, "params": {param_name: attack_value}, "json_body": None}

    def baseline(self, param_name):
        """
        FIXED: Get TRUE baseline by sending an empty string or benign value
        that won't trigger validation errors.
        """
        if param_name in self._baseline_cache:
            return self._baseline_cache[param_name]
        
        # For login forms, send a dummy email/username that looks legitimate
        # This avoids triggering "invalid syntax" validation errors
        context = self.detect_param_context()
        
        if isinstance(context, tuple) and param_name.lower() in ['username', 'user', 'email', 'login']:
            baseline_value = "test_user@example.com"
        elif isinstance(context, tuple) and param_name.lower() in ['password', 'pass', 'pwd']:
            baseline_value = "TestPass123!"
        else:
            baseline_value = "baseline_test_value"
        
        args = self.build_request_args(param_name, baseline_value)
        # Use fresh session for baseline to avoid state pollution
        resp = self.request(**args, fresh_session=True)
        
        # Cache the baseline
        self._baseline_cache[param_name] = resp
        return resp

    def get_baseline_time(self, param_name):
        start = time.time()
        resp = self.baseline(param_name)
        elapsed = time.time() - start
        if resp is None:
            return None, None
        return elapsed, resp.text

    def get_baseline_text(self, param_name):
        _, text = self.get_baseline_time(param_name)
        return text

    def _log(self, level, message):
        colors = {
            "INFO": Fore.CYAN,
            "FOUND": Fore.GREEN,
            "VULN": Fore.RED,
            "WARN": Fore.YELLOW,
        }
        color = colors.get(level, Fore.WHITE)
        print(f"{color}[{level}]{Style.RESET_ALL} {message}")

    def run_concurrent(self, tasks, worker_fn):
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(worker_fn, task): task for task in tasks}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception:
                    pass
        return results

    def unique_tag(self, prefix="KR"):
        return f"{prefix}_{uuid.uuid4().hex[:8].upper()}"
    
    def extract_forms_from_html(self, html):
        try:
            from bs4 import BeautifulSoup
            forms = []
            soup = BeautifulSoup(html, 'html.parser')
            
            for form_tag in soup.find_all('form'):
                form_info = {
                    'action': form_tag.get('action', ''),
                    'method': form_tag.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                    input_name = input_tag.get('name')
                    if not input_name:
                        continue
                    
                    input_type = input_tag.get('type', 'text').lower()
                    input_value = input_tag.get('value', '')
                    
                    form_info['inputs'].append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_value
                    })
                
                if form_info['inputs']:
                    forms.append(form_info)
            
            return forms
        except ImportError:
            self._log("WARN", "BeautifulSoup not installed. Form extraction limited.")
            return []
        except Exception:
            return []
    
    def extract_all_parameters_from_html(self, html):
        params = set()
        
        forms = self.extract_forms_from_html(html)
        for form in forms:
            for inp in form['inputs']:
                params.add(inp['name'])
        
        matches = FORM_INPUT_RE.findall(html)
        params.update(matches)
        
        return list(params)
    
    def get_html_content(self, path=""):
        resp = self.request(path, fresh_session=True)
        if resp:
            return resp.text
        return ""