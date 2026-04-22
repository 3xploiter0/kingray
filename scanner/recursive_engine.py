import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time


class ScanQueue:
    def __init__(self, initial_url, max_depth=3, max_urls=100):
        self.queue = []
        self.visited = set()
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.add_url(initial_url, depth=0)
    
    def add_url(self, url, depth=0):
        if len(self.visited) >= self.max_urls:
            return False
        if url in self.visited:
            return False
        if depth > self.max_depth:
            return False
        
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        
        self.queue.append((url, depth))
        self.visited.add(url)
        return True
    
    def get_next(self):
        if not self.queue:
            return None, None
        return self.queue.pop(0)
    
    def add_discovered_paths(self, base_url, paths, current_depth):
        added = 0
        for path in paths:
            full_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            if self.add_url(full_url, current_depth + 1):
                added += 1
        return added
    
    def __len__(self):
        return len(self.queue)


def extract_forms_from_html(html, base_url):
    forms = []
    try:
        soup = BeautifulSoup(html, 'html.parser')
        for form_tag in soup.find_all('form'):
            form_info = {
                'action': form_tag.get('action', ''),
                'method': form_tag.get('method', 'GET').upper(),
                'inputs': [],
                'full_url': urljoin(base_url, form_tag.get('action', ''))
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
    except Exception:
        pass
    
    return forms


def extract_links_from_html(html, base_url):
    links = []
    try:
        soup = BeautifulSoup(html, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith('#') or href.startswith('javascript:'):
                continue
            if href.startswith('mailto:') or href.startswith('tel:'):
                continue
            
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            if parsed.scheme in ('http', 'https'):
                links.append(full_url)
    except Exception:
        pass
    
    return links


def extract_parameters_from_html(html, current_url):
    params = []
    
    forms = extract_forms_from_html(html, current_url)
    for form in forms:
        for inp in form['inputs']:
            params.append(inp['name'])
    
    regex_patterns = [
        r'name=["\']([^"\']+)["\']',
        r'id=["\']([^"\']+)["\']',
        r'<input[^>]*name=["\']([^"\']+)["\']',
        r'<textarea[^>]*name=["\']([^"\']+)["\']',
        r'<select[^>]*name=["\']([^"\']+)["\']',
    ]
    
    for pattern in regex_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        params.extend(matches)
    
    return list(set(params))


class RecursiveScanner:
    def __init__(self, initial_url, threads=10, timeout=5, max_depth=3, max_urls=100, no_heuristic=False):
        from scanner.engine import Scanner
        
        self.initial_url = initial_url
        self.threads = threads
        self.timeout = timeout
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.no_heuristic = no_heuristic
        
        self.scan_queue = ScanQueue(initial_url, max_depth, max_urls)
        self.results = {
            'targets_scanned': [],
            'vulnerabilities': [],
            'discovered_urls': [],
            'forms_found': [],
            'tech_stack_by_url': {}
        }
        
        self.engine_cache = {}
    
    def get_engine_for_url(self, url):
        if url not in self.engine_cache:
            from scanner.engine import Scanner
            self.engine_cache[url] = Scanner(
                target_url=url,
                threads=self.threads,
                timeout=self.timeout
            )
        return self.engine_cache[url]
    
    def scan_url(self, url, depth):
        engine = self.get_engine_for_url(url)
        engine._log("INFO", f"Scanning URL (depth {depth}): {url}")
        
        resp = engine.request("", method="GET")
        if not resp:
            return None
        
        html = resp.text
        
        forms = extract_forms_from_html(html, url)
        for form in forms:
            self.results['forms_found'].append({
                'url': url,
                'action': form['action'],
                'method': form['method'],
                'inputs': form['inputs'],
                'full_url': form['full_url']
            })
        
        links = extract_links_from_html(html, url)
        for link in links:
            self.scan_queue.add_url(link, depth + 1)
        
        params = extract_parameters_from_html(html, url)
        
        scan_result = {
            'url': url,
            'depth': depth,
            'status_code': resp.status_code,
            'content_length': len(resp.content),
            'forms_found': len(forms),
            'parameters_found': params,
            'links_found': len(links)
        }
        
        self.results['targets_scanned'].append(scan_result)
        self.results['discovered_urls'].append(url)
        
        return scan_result
    
    def run_heuristic_on_url(self, url):
        from scanner.modules.heuristic import heuristic_detect
        engine = self.get_engine_for_url(url)
        tech, aggressive, fw_wordlist = heuristic_detect(engine)
        
        self.results['tech_stack_by_url'][url] = {
            'technologies': tech,
            'aggressive_mode': aggressive,
            'framework_wordlist': fw_wordlist
        }
        
        return tech
    
    def run_vulnerability_checks(self, url):
        engine = self.get_engine_for_url(url)
        
        vuln_results = {}
        
        try:
            from scanner.modules.sqli import sqli_check
            vuln_results['sqli'] = sqli_check(engine)
        except Exception as e:
            vuln_results['sqli'] = []
        
        try:
            from scanner.modules.xss import xss_check
            vuln_results['xss'] = xss_check(engine)
        except Exception as e:
            vuln_results['xss'] = []
        
        try:
            from scanner.modules.auth import auth_check
            vuln_results['auth'] = auth_check(engine)
        except Exception as e:
            vuln_results['auth'] = []
        
        for vuln_type, findings in vuln_results.items():
            for finding in findings:
                finding['url'] = url
                self.results['vulnerabilities'].append({
                    'type': vuln_type,
                    'url': url,
                    'details': finding
                })
        
        return vuln_results
    
    def run_directory_busting(self, url, depth):
        from scanner.modules.dirbust import dirbust, get_default_wordlist
        engine = self.get_engine_for_url(url)
        
        paths = get_default_wordlist()
        discovered_paths = []
        
        def check_path(path):
            resp = engine.request(path)
            if resp and resp.status_code in (200, 201, 204, 301, 302, 403):
                full_url = resp.url
                if self.scan_queue.add_url(full_url, depth + 1):
                    discovered_paths.append(full_url)
                return {
                    "url": resp.url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "path": path,
                }
            return None
        
        results = engine.run_concurrent(paths, check_path)
        
        engine._log("INFO", f"Directory busting on {url} found {len(discovered_paths)} new URLs")
        
        return results
    
    def run(self):
        total_scanned = 0
        
        while self.scan_queue:
            url, depth = self.scan_queue.get_next()
            if not url:
                break
            
            engine = self.get_engine_for_url(url)
            engine._log("INFO", f"Processing URL (depth {depth}): {url}")
            
            scan_result = self.scan_url(url, depth)
            if not scan_result:
                continue
            
            if not self.no_heuristic:
                self.run_heuristic_on_url(url)
            
            self.run_vulnerability_checks(url)
            
            if depth < self.max_depth:
                dir_results = self.run_directory_busting(url, depth)
                scan_result['dirbust_results'] = len(dir_results)
            
            total_scanned += 1
            
            if total_scanned >= self.max_urls:
                engine._log("INFO", f"Reached maximum URL limit ({self.max_urls})")
                break
        
        return self.results