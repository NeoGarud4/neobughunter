#!/usr/bin/env python3
"""
NEO GARUD4 Bug Hunter - Advanced Web Vulnerability Scanner
Command Line Interface Version
For authorized security testing only
"""
import requests
import urllib3
import threading
from bs4 import BeautifulSoup
import time
from urllib.parse import urljoin, urlparse
import json
import argparse
from concurrent.futures import ThreadPoolExecutor

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NeoGarud4Scanner:
    def __init__(self, target_url, threads=10, timeout=10):
        self.target_url = target_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (NEO GARUD4 Bug Hunter) AppleWebKit/537.36'
        })
        self.findings = {
            'info_disclosures': [],
            'xss_points': [],
            'sql_injection_points': [],
            'open_redirects': [],
            'security_headers_missing': [],
            'server_info': {}
        }
        
    def print_banner(self):
        banner = """
    ███╗   ██╗███████╗ ██████╗  █████╗ ██╗   ██╗██████╗  █████╗ ██████╗ 
    ████╗  ██║██╔════╝██╔════╝ ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██╔██╗ ██║█████╗  ██║  ███╗███████║██║   ██║██║  ██║███████║██████╔╝
    ██║╚██╗██║██╔══╝  ██║   ██║██╔══██║██║   ██║██║  ██║██╔══██║██╔══██╗
    ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝██████╔╝██║  ██║██║  ██║
    ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    
    Advanced Web Vulnerability Scanner
    For authorized security testing only
        """
        print(banner)
        
    def scan_target(self):
        self.print_banner()
        print(f"[+] NEO GARUD4 Bug Hunter - Scanning: {self.target_url}")
        start_time = time.time()
        
        # Get server info first
        self._get_server_info()
        
        # Crawl and scan pages
        urls_to_scan = self._crawl_site()
        
        # Scan with thread pool
        print(f"[+] Found {len(urls_to_scan)} URLs to scan")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._scan_page, url) for url in urls_to_scan]
            for future in futures:
                future.result()
        
        # Additional checks
        self._check_security_headers()
        self._check_directory_listings()
        
        # Print results
        self._generate_report()
        print(f"[+] Scan completed in {time.time() - start_time:.2f} seconds")
        return self.findings

    def _get_server_info(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            self.findings['server_info'] = {
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Not Specified'),
                'powered_by': response.headers.get('X-Powered-By', 'Not Specified'),
                'content_type': response.headers.get('Content-Type', ''),
                'cookies': dict(response.cookies)
            }
            print(f"[+] Server Info: {self.findings['server_info']['server']}")
        except Exception as e:
            print(f"[-] Error getting server info: {str(e)}")
            
    def _crawl_site(self):
        urls = set()
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find links
            for link in soup.find_all('a', href=True):
                url = urljoin(self.target_url, link['href'])
                if self._is_same_domain(url):
                    urls.add(url)
                    
            # Find forms
            for form in soup.find_all('form', action=True):
                url = urljoin(self.target_url, form['action'])
                if self._is_same_domain(url):
                    urls.add(url)
                    
        except Exception as e:
            print(f"[-] Crawl error: {str(e)}")
            
        urls.add(self.target_url)  # Include main target
        print(f"[+] Crawled {len(urls)} URLs")
        return list(urls)
        
    def _is_same_domain(self, url):
        return urlparse(url).netloc == urlparse(self.target_url).netloc

    def _scan_page(self, url):
        print(f"[+] Scanning: {url}")
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            # Check for info disclosure
            self._check_info_disclosure(response, url)
            
            # Check for XSS
            self._check_xss_points(url)
            
            # Check for SQLi
            self._check_sqli_points(url)
            
            # Check for open redirects
            self._check_open_redirects(url)
            
        except Exception as e:
            pass
            
    def _check_info_disclosure(self, response, url):
        content = response.text.lower()
        sensitive_keywords = ['password', 'username', 'admin', 'root', 'private key', 'secret']
        found_keywords = [kw for kw in sensitive_keywords if kw in content]
        
        if found_keywords:
            self.findings['info_disclosures'].append({
                'url': url,
                'keywords': found_keywords,
                'type': 'Sensitive Info Disclosure'
            })
            print(f"[!] Info Disclosure found at {url}")
            
    def _check_xss_points(self, url):
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ]
        
        # Test reflected parameters
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = {}
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[key] = value
                        
                for key in params:
                    original_value = params[key]
                    for payload in xss_payloads:
                        params[key] = payload
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?"
                        test_url += "&".join([f"{k}={v}" for k, v in params.items()])
                        
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                        if payload in response.text:
                            self.findings['xss_points'].append({
                                'url': test_url,
                                'parameter': key,
                                'payload': payload,
                                'type': 'Reflected XSS'
                            })
                            print(f"[!] XSS found at {test_url}")
                        params[key] = original_value
                        
        except Exception as e:
            pass
            
    def _check_sqli_points(self, url):
        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "ora-01756",
            "postgresql query failed"
        ]
        
        sqli_payloads = ["'", "\"", "')", "\")"]
        
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = {}
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[key] = value
                        
                for key in params:
                    original_value = params[key]
                    for payload in sqli_payloads:
                        params[key] = payload
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?"
                        test_url += "&".join([f"{k}={v}" for k, v in params.items()])
                        
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                        for error in sql_errors:
                            if error in response.text.lower():
                                self.findings['sql_injection_points'].append({
                                    'url': test_url,
                                    'parameter': key,
                                    'payload': payload,
                                    'error': error,
                                    'type': 'Error-based SQL Injection'
                                })
                                print(f"[!] SQLi found at {test_url}")
                        params[key] = original_value
                        
        except Exception as e:
            pass
            
    def _check_open_redirects(self, url):
        redirect_payloads = [
            "//example.com",
            "https://example.com",
            "/example.com",
            "\\\\example.com"
        ]
        
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = {}
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[key] = value
                        
                for key in params:
                    original_value = params[key]
                    for payload in redirect_payloads:
                        params[key] = payload
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?"
                        test_url += "&".join([f"{k}={v}" for k, v in params.items()])
                        
                        response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if 'example.com' in location:
                                self.findings['open_redirects'].append({
                                    'url': test_url,
                                    'parameter': key,
                                    'payload': payload,
                                    'location': location,
                                    'type': 'Open Redirect'
                                })
                                print(f"[!] Open Redirect found at {test_url}")
                        params[key] = original_value
                        
        except Exception as e:
            pass
            
    def _check_security_headers(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=31536000',
                'Content-Security-Policy': None
            }
            
            missing_headers = []
            for header, expected_value in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
                elif expected_value and expected_value not in headers.get(header, ''):
                    missing_headers.append(f"{header} (incorrect value)")
            
            if missing_headers:
                self.findings['security_headers_missing'].append({
                    'url': self.target_url,
                    'missing_headers': missing_headers,
                    'type': 'Missing Security Headers'
                })
                print(f"[!] Missing security headers: {', '.join(missing_headers)}")
                
        except Exception as e:
            pass
            
    def _check_directory_listings(self):
        common_dirs = ['/admin', '/backup', '/config', '/logs', '/tmp', '/uploads']
        for dir_path in common_dirs:
            try:
                url = self.target_url + dir_path
                response = self.session.get(url, timeout=self.timeout, verify=False)
                
                # Check for directory listing
                if "Index of" in response.text or "Directory Listing" in response.text:
                    self.findings['info_disclosures'].append({
                        'url': url,
                        'type': 'Directory Listing Enabled'
                    })
                    print(f"[!] Directory listing enabled at {url}")
                    
            except Exception as e:
                pass
                
    def _generate_report(self):
        print("\n" + "="*60)
        print("NEO GARUD4 BUG HUNTER - RESULTS")
        print("="*60)
        
        # Server Info
        if self.findings['server_info']:
            print("\n[+] SERVER INFORMATION:")
            for key, value in self.findings['server_info'].items():
                print(f"   {key}: {value}")
                
        # Vulnerabilities
        vuln_categories = {
            'XSS Points': self.findings['xss_points'],
            'SQL Injection Points': self.findings['sql_injection_points'],
            'Open Redirects': self.findings['open_redirects'],
            'Info Disclosures': self.findings['info_disclosures'],
            'Missing Security Headers': self.findings['security_headers_missing']
        }
        
        total_vulns = 0
        for category, issues in vuln_categories.items():
            if issues:
                print(f"\n[!] {category.upper()}:")
                for issue in issues:
                    print(f"   - {issue.get('url', 'N/A')}")
                    if 'parameter' in issue:
                        print(f"     Parameter: {issue['parameter']}")
                    if 'payload' in issue:
                        print(f"     Payload: {issue['payload']}")
                    if 'type' in issue:
                        print(f"     Type: {issue['type']}")
                    total_vulns += 1
                        
        if total_vulns == 0:
            print("\n[+] No immediate vulnerabilities found (manual verification recommended)")
        else:
            print(f"\n[!] TOTAL VULNERABILITIES FOUND: {total_vulns}")
            
        print("\n" + "="*60)

def main():
    parser = argparse.ArgumentParser(description='NEO GARUD4 Bug Hunter - Advanced Web Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url
        
    scanner = NeoGarud4Scanner(args.url, args.threads, args.timeout)
    findings = scanner.scan_target()
    
    # Export results if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(findings, f, indent=4)
            print(f"[+] Results saved to {args.output}")
        except Exception as e:
            print(f"[-] Failed to save results: {str(e)}")

if __name__ == "__main__":
    main()
