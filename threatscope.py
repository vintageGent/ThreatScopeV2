#!/home/seeker/ThreatScopeV2/venv/bin/python3

import json
import sys
from urllib.parse import urlparse
from modules.network import run_network_scan
from modules.vuln_scanners import check_sql_injection, check_xss, check_sensitive_files, check_directory_traversal, check_insecure_headers
from modules.dependency_scanner import scan_dependencies
from modules.secrets_scanner import scan_secrets
from modules.reporter import generate_html_report, generate_pdf_report, generate_advice_report

def display_banner():
    print("\n" + "="*60)
    print(r"""
  _______ _                     _    _____
 |__   __| |                   | |  / ____|
    | |  | |__  _ __ ___  __ _ | |_| (___   ___  _ __   ___
    | |  | '_ \| '__/ _ \/ _` || __|\___ \ / _ \| '_ \ / _ \
    | |  | | | | | |  __/ (_| || |_ ____) | (_) | |_) |  __/
    |_|  |_| |_|_|  \___|\__,_| \__|_____/ \___/| .__/ \___|
                                                | |
                                                |_|
    """)
    print("="*60)
    print("  Threat Sope: Focused Network & Vulnerability Scanner - Interactive Mode")
    print("="*60)
    print("\nWelcome to Threat Sope! This tool helps you perform network scans,")
    print("vulnerability assessments, dependency checks, and secret scans.")
    print("\nInstructions:")
    print("1. Choose a scan type from the menu.")
    print("2. Follow the prompts for target information and any additional options.")
    print("3. You'll have the option to generate various reports after each scan.")
    print("\n" + "="*60 + "\n")

def get_user_input(prompt, default=None):
    while True:
        user_input = input(prompt).strip()
        if user_input:
            return user_input
        elif default is not None:
            return default
        else:
            print("Input cannot be empty. Please try again.")

def get_url_input(prompt):
    while True:
        url = get_user_input(prompt)
        if url.startswith("http://") or url.startswith("https://"):
            return url
        else:
            print("Invalid URL. Please include http:// or https://")

def get_file_or_dir_input(prompt):
    while True:
        path = get_user_input(prompt)
        # Basic check, can be enhanced with os.path.exists if needed
        if path:
            return path
        else:
            print("Path cannot be empty. Please try again.")

def handle_reporting(scan_results):
    if not scan_results:
        return

    print("\n--- Reporting Options ---")
    html_file = get_user_input("Save HTML report to (e.g., report.html, leave blank to skip): ", "")
    pdf_file = get_user_input("Save PDF report to (e.g., report.pdf, leave blank to skip): ", "")
    advice_file = get_user_input("Save remediation advice to (e.g., advice.txt, leave blank to skip): ", "")

    if html_file:
        try:
            generate_html_report(scan_results, html_file)
            print(f"[+] HTML report saved to {html_file}")
        except Exception as e:
            print(f"[!] Error generating HTML report: {e}")
    if pdf_file:
        try:
            generate_pdf_report(scan_results, pdf_file)
            print(f"[+] PDF report saved to {pdf_file}")
        except Exception as e:
            print(f"[!] Error generating PDF report: {e}")
    if advice_file:
        try:
            generate_advice_report(scan_results, advice_file)
            print(f"[+] Advice report saved to {advice_file}")
        except Exception as e:
            print(f"[!] Error generating advice report: {e}")

def run_netscan_interactive():
    target = get_user_input("Enter the target IP address or range (e.g., 192.168.1.1 or 192.168.1.0/24): ")
    ports_input = get_user_input("Enter comma-separated ports to scan (e.g., 80,443,22) or leave blank for common ports: ", "")
    port_list = [int(p.strip()) for p in ports_input.split(',')] if ports_input else None
    
    print(f"\n[+] Running network scan on {target}...")
    try:
        scan_results = run_network_scan(target, port_list)
        if scan_results:
            print("\n--- Network Scan Results ---")
            print(json.dumps(scan_results, indent=2)) # Assuming run_network_scan returns a dict
            handle_reporting(scan_results)
        else:
            print("[!] No results from network scan.")
    except Exception as e:
        print(f"[!] An error occurred during network scan: {e}")

def run_vulnscan_interactive():
    url = get_url_input("Enter the URL to scan for vulnerabilities (e.g., https://example.com/login.php?id=1): ")
    
    print(f"\n[+] Running web vulnerability scan on {url}...")
    try:
        all_findings = []
        print("\n--- Checking for SQL Injection ---")
        all_findings.extend(check_sql_injection(url))
        print("\n--- Checking for Cross-Site Scripting (XSS) ---")
        all_findings.extend(check_xss(url))
        print("\n--- Checking for Sensitive Files ---")
        all_findings.extend(check_sensitive_files(url))
        print("\n--- Checking for Directory Traversal ---")
        all_findings.extend(check_directory_traversal(url))
        print("\n--- Checking for Insecure Headers ---")
        all_findings.extend(check_insecure_headers(url))

        scan_results = {
            "target": url,
            "scan_type": "Web Vulnerability Scan",
            "vulnerabilities": all_findings
        }

        if not all_findings:
            print("\n[+] No web vulnerabilities found.")
        else:
            print(f"\n[!] Scan complete. Found {len(all_findings)} potential web vulnerability/ies.")
            for finding in all_findings:
                print(f"  [!] {finding.get('type', 'Unknown')} found at {finding.get('url', url)}")
                print(f"    - Details: {finding.get('details', 'N/A')}")
                print("-" * 20)
            handle_reporting(scan_results)

    except Exception as e:
        print(f"[!] An error occurred during web vulnerability scan: {e}")

def run_depscan_interactive():
    file_path = get_file_or_dir_input("Enter the path to the dependency file (e.g., requirements.txt, package.json): ")
    
    print(f"\n[+] Running dependency scan on {file_path}...")
    try:
        scan_results = scan_dependencies(file_path)
        if scan_results:
            print("\n--- Dependency Scan Results ---")
            print(json.dumps(scan_results, indent=2)) # Assuming scan_dependencies returns a dict
            handle_reporting(scan_results)
        else:
            print("[!] No results from dependency scan.")
    except Exception as e:
        print(f"[!] An error occurred during dependency scan: {e}")

def run_secretscan_interactive():
    path = get_file_or_dir_input("Enter the path to the file or directory to scan for secrets: ")
    
    print(f"\n[+] Running secret scan on {path}...")
    try:
        scan_results = scan_secrets(path)
        if scan_results:
            print("\n--- Secret Scan Results ---")
            print(json.dumps(scan_results, indent=2)) # Assuming scan_secrets returns a dict
            handle_reporting(scan_results)
        else:
            print("[!] No results from secret scan.")
    except Exception as e:
        print(f"[!] An error occurred during secret scan: {e}")

def main_interactive():
    display_banner()
    
    while True:
        print("\n--- Choose a Scan Type ---")
        print("1. Network Scan (netscan)")
        print("2. Web Vulnerability Scan (vulnscan)")
        print("3. Dependency Scan (dep_scan)")
        print("4. Secret Scan (secret_scan)")
        print("5. Exit")

        choice = get_user_input("Enter your choice (1-5): ")

        if choice == '1':
            run_netscan_interactive()
        elif choice == '2':
            run_vulnscan_interactive()
        elif choice == '3':
            run_depscan_interactive()
        elif choice == '4':
            run_secretscan_interactive()
        elif choice == '5':
            print("Exiting Threat Sope. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

if __name__ == "__main__":
    main_interactive()
