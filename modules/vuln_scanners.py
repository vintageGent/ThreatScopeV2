import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

# --- SQL Injection Scanner --- #
SQL_ERRORS = [
    r"you have an error in your sql syntax;",
    r"warning: mysql_fetch_array()",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
]
SQLI_PAYLOADS = ["'", "' OR 1=1--", "' OR '1'='1'", "\" OR 1=1--"]

def check_sql_injection(url):
    print(f"[*] Scanning for SQL injection...")
    findings = []
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action)
            inputs = form.find_all(['input', 'textarea'])
            for payload in SQLI_PAYLOADS:
                data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        data[name] = payload if input_tag.get('type', 'text') in ['text', 'search', 'textarea'] else input_tag.get('value', '')
                if not data: continue
                
                res = requests.post(form_url, data=data, timeout=10) if method == 'post' else requests.get(form_url, params=data, timeout=10)
                for error in SQL_ERRORS:
                    if re.search(error, res.text, re.IGNORECASE):
                        findings.append({"type": "SQL Injection", "url": form_url, "payload": payload, "details": f"Detected error: {error}"})
                        break # Move to next payload
    except requests.RequestException:
        pass # Ignore network errors for this refactor
    return findings

# --- XSS (Cross-Site Scripting) Scanner --- #
XSS_PAYLOAD = "<script>alert('xss-test')</script>"

def check_xss(url):
    print(f"[*] Scanning for XSS...")
    findings = []
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action)
            inputs = form.find_all(['input', 'textarea'])
            data = {}
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    data[name] = XSS_PAYLOAD if input_tag.get('type', 'text') in ['text', 'search', 'textarea'] else input_tag.get('value', '')
            if not data: continue

            res = requests.post(form_url, data=data, timeout=10) if method == 'post' else requests.get(form_url, params=data, timeout=10)
            if XSS_PAYLOAD in res.text:
                findings.append({"type": "Cross-Site Scripting (XSS)", "url": form_url, "payload": XSS_PAYLOAD, "details": "Payload reflected in response."})
    except requests.RequestException:
        pass
    return findings

# --- Sensitive File Scanner --- #
SENSITIVE_PATHS = [
    '/.git/config', '/.env', '/.aws/credentials', '/backup.sql', '/dump.sql',
    '/database.yml', '/config.php.bak', '/wp-config.php', '/wp-admin'
]

def check_sensitive_files(url):
    print(f"[*] Scanning for sensitive files...")
    findings = []
    base_url = url.rstrip('/')
    for path in SENSITIVE_PATHS:
        full_url = base_url + path
        try:
            response = requests.head(full_url, timeout=5, allow_redirects=True)
            if response.status_code == 200:
                findings.append({"type": "Sensitive File Exposure", "url": full_url, "details": f"File/directory accessible with status code {response.status_code}."})
        except requests.RequestException:
            pass
    return findings

# --- Directory Traversal Scanner --- #
TRAVERSAL_PAYLOADS = ["../../../../etc/passwd", "..\\..\\..\\..\\boot.ini"]

def check_directory_traversal(url):
    print(f"[*] Scanning for Directory Traversal...")
    findings = []
    parsed_url = urlparse(url)
    for payload in TRAVERSAL_PAYLOADS:
        malicious_url = f"{parsed_url.scheme}://{parsed_url.netloc}/{payload}"
        try:
            response = requests.get(malicious_url, timeout=10)
            if ("root:x:0:0" in response.text) or ("[boot loader]" in response.text):
                findings.append({"type": "Directory Traversal", "url": malicious_url, "payload": payload, "details": "Server responded with sensitive file content."})
        except requests.RequestException:
            pass
    return findings

# --- Insecure HTTP Headers Scanner --- #
SECURITY_HEADERS = ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"]

def check_insecure_headers(url):
    print(f"[*] Scanning for insecure headers...")
    findings = []
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        for header in SECURITY_HEADERS:
            if header not in headers:
                findings.append({"type": "Missing Security Header", "url": url, "details": f"Missing recommended security header: {header}"})
    except requests.RequestException:
        pass
    return findings
