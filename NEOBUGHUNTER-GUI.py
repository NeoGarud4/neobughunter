#!/usr/bin/env python3
"""
NEO GARUD4 Bug Hunter - Advanced Web Vulnerability Scanner
Graphical User Interface Version
For authorized security testing only
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import requests
import urllib3
import threading
from bs4 import BeautifulSoup
import time
from urllib.parse import urljoin, urlparse
import json
import socket
from concurrent.futures import ThreadPoolExecutor
import webbrowser

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NeoGarud4GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NEO GARUD4 Bug Hunter")
        self.root.geometry("1000x700")
        self.root.configure(bg='#0a0a0a')
        self.root.resizable(True, True)
        
        # Scanner variables
        self.scanner = None
        self.scan_thread = None
        self.is_scanning = False
        
        # Create custom style
        self.setup_styles()
        self.create_widgets()
        
    def setup_styles(self):
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Custom styles
        self.style.configure('TFrame', background='#0a0a0a')
        self.style.configure('TLabel', background='#0a0a0a', foreground='#00ff00', font=('Courier', 10))
        self.style.configure('TButton', background='#1a1a1a', foreground='#00ff00', font=('Courier', 9, 'bold'))
        self.style.map('TButton', background=[('active', '#2a2a2a')])
        self.style.configure('Header.TLabel', font=('Courier', 14, 'bold'), foreground='#ff0000')
        self.style.configure('Title.TLabel', font=('Courier', 12, 'bold'), foreground='#00ff00')
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header with ASCII art
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ascii_art = """
    ███╗   ██╗███████╗ ██████╗  █████╗ ██╗   ██╗██████╗  █████╗ ██████╗ 
    ████╗  ██║██╔════╝██╔════╝ ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██╔██╗ ██║█████╗  ██║  ███╗███████║██║   ██║██║  ██║███████║██████╔╝
    ██║╚██╗██║██╔══╝  ██║   ██║██╔══██║██║   ██║██║  ██║██╔══██║██╔══██╗
    ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝██████╔╝██║  ██║██║  ██║
    ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
        """
        
        ascii_label = ttk.Label(header_frame, text=ascii_art, justify=tk.CENTER, style='Header.TLabel')
        ascii_label.pack()
        
        # Target input frame
        target_frame = ttk.Frame(main_frame)
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(target_frame, text="Target URL:", style='Title.TLabel').pack(anchor=tk.W)
        self.url_entry = ttk.Entry(target_frame, font=('Courier', 10), width=70)
        self.url_entry.pack(fill=tk.X, pady=(5, 0))
        self.url_entry.insert(0, "https://example.com")
        
        # Options frame
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Threads
        threads_frame = ttk.Frame(options_frame)
        threads_frame.pack(side=tk.LEFT, padx=(0, 20))
        ttk.Label(threads_frame, text="Threads:", style='TLabel').pack(anchor=tk.W)
        self.threads_var = tk.StringVar(value="10")
        threads_entry = ttk.Entry(threads_frame, textvariable=self.threads_var, width=10, font=('Courier', 10))
        threads_entry.pack()
        
        # Timeout
        timeout_frame = ttk.Frame(options_frame)
        timeout_frame.pack(side=tk.LEFT, padx=(0, 20))
        ttk.Label(timeout_frame, text="Timeout (s):", style='TLabel').pack(anchor=tk.W)
        self.timeout_var = tk.StringVar(value="10")
        timeout_entry = ttk.Entry(timeout_frame, textvariable=self.timeout_var, width=10, font=('Courier', 10))
        timeout_entry.pack()
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_button = ttk.Button(buttons_frame, text="▶ START SCAN", command=self.start_scan)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(buttons_frame, text="⏹ STOP SCAN", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_button = ttk.Button(buttons_frame, text="💾 EXPORT RESULTS", command=self.export_results, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(0, 10))
        
        # Results notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Server info tab
        self.server_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.server_frame, text="🌐 Server Info")
        self.server_text = scrolledtext.ScrolledText(self.server_frame, wrap=tk.WORD, bg='#1a1a1a', fg='#00ff00', font=('Courier', 9))
        self.server_text.pack(fill=tk.BOTH, expand=True)
        
        # Vulnerabilities tab
        self.vulns_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.vulns_frame, text="⚠️ Vulnerabilities")
        self.vulns_text = scrolledtext.ScrolledText(self.vulns_frame, wrap=tk.WORD, bg='#1a1a1a', fg='#ff5555', font=('Courier', 9))
        self.vulns_text.pack(fill=tk.BOTH, expand=True)
        
        # XSS tab
        self.xss_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.xss_frame, text="💉 XSS Points")
        self.xss_text = scrolledtext.ScrolledText(self.xss_frame, wrap=tk.WORD, bg='#1a1a1a', fg='#ffff00', font=('Courier', 9))
        self.xss_text.pack(fill=tk.BOTH, expand=True)
        
        # SQLi tab
        self.sqli_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.sqli_frame, text="🧨 SQL Injection")
        self.sqli_text = scrolledtext.ScrolledText(self.sqli_frame, wrap=tk.WORD, bg='#1a1a1a', fg='#ff5555', font=('Courier', 9))
        self.sqli_text.pack(fill=tk.BOTH, expand=True)
        
        # Logs tab
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="📝 Logs")
        self.logs_text = scrolledtext.ScrolledText(self.logs

            # Logs tab
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="📝 Logs")
        self.logs_text = scrolledtext.ScrolledText(self.logs_frame, wrap=tk.WORD, bg='#1a1a1a', fg='#00ff00', font=('Courier', 9))
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=(10, 0))
        
    def log_message(self, message):
        timestamp = time.strftime("[%H:%M:%S]")
        self.logs_text.insert(tk.END, f"{timestamp} {message}\n")
        self.logs_text.see(tk.END)
        self.root.update_idletasks()
        
    def start_scan(self):
        target_url = self.url_entry.get().strip()
        if not target_url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        # Validate URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, target_url)
            
        try:
            threads = int(self.threads_var.get())
            timeout = int(self.timeout_var.get())
        except ValueError:
            messagebox.showerror("Error", "Threads and timeout must be valid numbers")
            return
            
        # Disable start button and enable stop button
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.DISABLED)
        self.progress.start()
        self.status_var.set("Scanning...")
        self.is_scanning = True
        
        # Clear previous results
        self.clear_results()
        
        # Start scanning in a separate thread
        self.scanner = NeoGarud4ScannerGUI(target_url, threads, timeout, self)
        self.scan_thread = threading.Thread(target=self.scanner.scan_target)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        # Check for completion
        self.check_scan_completion()
        
    def stop_scan(self):
        self.is_scanning = False
        self.status_var.set("Scan stopped")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()
        self.log_message("Scan manually stopped by user")
        
    def check_scan_completion(self):
        if self.scan_thread and self.scan_thread.is_alive() and self.is_scanning:
            self.root.after(100, self.check_scan_completion)
        else:
            if self.is_scanning:  # Completed normally
                self.status_var.set("Scan completed")
                self.export_button.config(state=tk.NORMAL)
                self.log_message("Scan completed successfully")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.progress.stop()
            
    def clear_results(self):
        self.server_text.delete(1.0, tk.END)
        self.vulns_text.delete(1.0, tk.END)
        self.xss_text.delete(1.0, tk.END)
        self.sqli_text.delete(1.0, tk.END)
        self.logs_text.delete(1.0, tk.END)
        
    def update_server_info(self, server_info):
        info_text = f"""Server Information:
==================
Status Code: {server_info.get('status_code', 'N/A')}
Server: {server_info.get('server', 'Not Specified')}
Powered By: {server_info.get('powered_by', 'Not Specified')}
Content Type: {server_info.get('content_type', 'N/A')}

Cookies:
--------
"""
        for name, value in server_info.get('cookies', {}).items():
            info_text += f"{name}: {value}\n"
            
        self.server_text.insert(tk.END, info_text)
        
    def update_vulnerabilities(self, findings):
        # General vulnerabilities
        if findings['info_disclosures']:
            self.vulns_text.insert(tk.END, "INFO DISCLOSURES:\n")
            self.vulns_text.insert(tk.END, "==================\n")
            for issue in findings['info_disclosures']:
                self.vulns_text.insert(tk.END, f"URL: {issue['url']}\n")
                self.vulns_text.insert(tk.END, f"Type: {issue['type']}\n")
                if 'keywords' in issue:
                    self.vulns_text.insert(tk.END, f"Keywords: {', '.join(issue['keywords'])}\n")
                self.vulns_text.insert(tk.END, "\n")
                
        if findings['open_redirects']:
            self.vulns_text.insert(tk.END, "OPEN REDIRECTS:\n")
            self.vulns_text.insert(tk.END, "================\n")
            for issue in findings['open_redirects']:
                self.vulns_text.insert(tk.END, f"URL: {issue['url']}\n")
                self.vulns_text.insert(tk.END, f"Parameter: {issue['parameter']}\n")
                self.vulns_text.insert(tk.END, f"Payload: {issue['payload']}\n")
                self.vulns_text.insert(tk.END, f"Location: {issue['location']}\n")
                self.vulns_text.insert(tk.END, f"Type: {issue['type']}\n\n")
                
        if findings['security_headers_missing']:
            self.vulns_text.insert(tk.END, "MISSING SECURITY HEADERS:\n")
            self.vulns_text.insert(tk.END, "==========================\n")
            for issue in findings['security_headers_missing']:
                self.vulns_text.insert(tk.END, f"URL: {issue['url']}\n")
                self.vulns_text.insert(tk.END, f"Missing Headers: {', '.join(issue['missing_headers'])}\n")
                self.vulns_text.insert(tk.END, f"Type: {issue['type']}\n\n")
                
        # XSS vulnerabilities
        if findings['xss_points']:
            for issue in findings['xss_points']:
                self.xss_text.insert(tk.END, f"URL: {issue['url']}\n")
                self.xss_text.insert(tk.END, f"Parameter: {issue['parameter']}\n")
                self.xss_text.insert(tk.END, f"Payload: {issue['payload']}\n")
                self.xss_text.insert(tk.END, f"Type: {issue['type']}\n\n")
                
        # SQLi vulnerabilities
        if findings['sql_injection_points']:
            for issue in findings['sql_injection_points']:
                self.sqli_text.insert(tk.END, f"URL: {issue['url']}\n")
                self.sqli_text.insert(tk.END, f"Parameter: {issue['parameter']}\n")
                self.sqli_text.insert(tk.END, f"Payload: {issue['payload']}\n")
                self.sqli_text.insert(tk.END, f"Error: {issue['error']}\n")
                self.sqli_text.insert(tk.END, f"Type: {issue['type']}\n\n")
                
    def export_results(self):
        findings = self.scanner.findings if self.scanner else {}
        if not findings:
            messagebox.showinfo("Info", "No results to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(findings, f, indent=4)
                messagebox.showinfo("Success", f"Results exported to {file_path}")
                self.log_message(f"Results exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {str(e)}")
                self.log_message(f"Failed to export results: {str(e)}")

class NeoGarud4ScannerGUI:
    def __init__(self, target_url, threads, timeout, gui_callback):
        self.target_url = target_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.gui_callback = gui_callback
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
        self.gui_callback.log_message(f"Scanner initialized for {self.target_url}")
        
    def scan_target(self):
        try:
            self.gui_callback.log_message(f"Starting scan of {self.target_url}")
            
            # Get server info first
            self._get_server_info()
            
            # Crawl and scan pages
            urls_to_scan = self._crawl_site()
            
            # Scan with thread pool
            self.gui_callback.log_message(f"Found {len(urls_to_scan)} URLs to scan")
            
            # Process URLs in batches to avoid freezing GUI
            batch_size = max(1, self.threads // 2)
            for i in range(0, len(urls_to_scan), batch_size):
                if not self.gui_callback.is_scanning:
                    break
                    
                batch = urls_to_scan[i:i + batch_size]
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = [executor.submit(self._scan_page, url) for url in batch]
                    for future in futures:
                        if not self.gui_callback.is_scanning:
                            break
                        future.result()
                        
                # Update GUI with current findings
                self.gui_callback.root.after(0, self.gui_callback.update_vulnerabilities, self.findings)
                
            # Additional checks
            self._check_security_headers()
            self._check_directory_listings()
            
            # Update GUI with final results
            self.gui_callback.root.after(0, self.gui_callback.update_server_info, self.findings['server_info'])
            self.gui_callback.root.after(0, self.gui_callback.update_vulnerabilities, self.findings)
            
        except Exception as e:
            self.gui_callback.log_message(f"Scan error: {str(e)}")
            
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
            self.gui_callback.log_message(f"Server Info: {self.findings['server_info']['server']}")
        except Exception as e:
            self.gui_callback.log_message(f"Error getting server info: {str(e)}")
            
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
            self.gui_callback.log_message(f"Crawl error: {str(e)}")
            
        urls.add(self.target_url)  # Include main target
        self.gui_callback.log_message(f"Crawled {len(urls)} URLs")
        return list(urls)
        
    def _is_same_domain(self, url):
        return urlparse(url).netloc == urlparse(self.target_url).netloc

    def _scan_page(self, url):
        self.gui_callback.log_message(f"Scanning: {url}")
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
            self.gui_callback.root.after(0, self.gui_callback.log_message, f"Info Disclosure found at {url}")
            
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
                            self.gui_callback.root.after(0, self.gui_callback.log_message, f"XSS found at {test_url}")
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
                                self.gui_callback.root.after(0, self.gui_callback.log_message, f"SQLi found at {test_url}")
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
                                self.gui_callback.root.after(0, self.gui_callback.log_message, f"Open Redirect found at {test_url}")
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
                self.gui_callback.root.after(0, self.gui_callback.log_message, f"Missing security headers: {', '.join(missing_headers)}")
                
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
                    self.gui_callback.root.after(0, self.gui_callback.log_message, f"Directory listing enabled at {url}")
                    
            except Exception as e:
                pass

def main():
    root = tk.Tk()
    app = NeoGarud4GUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
