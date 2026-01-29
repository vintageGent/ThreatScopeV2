import sys
import os
import argparse
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
    | |  | |__  _ __ ___  __ _ | |_| (___   ___ ___  _ __   ___
    | |  | '_ \| '__/ _ \/ _` || __|\___ \ / __/ _ \| '_ \ / _ \
    | |  | | | | | |  __/ (_| || |_ ____) | (_| (_) | |_) |  __/
    |_|  |_| |_|_|  \___|\__,_| \__|_____/ \___\___/| .__/ \___|
                                                    | |
                                                    |_|
    """)
    print("="*60)
    print("  Threat Scope: Focused Network & Vulnerability Scanner - Interactive Mode")
    print("="*60)
    print("\nWelcome to Threat Scope! This tool helps you perform network scans,")
    print("vulnerability assessments, dependency checks, and secret scans.")
    print("\nInstructions:")
    print("1. Choose a scan type from the menu.")
    print("2. Follow the prompts for target information and any additional options.")
    print("3. You'll have the option to generate various reports after each scan.")

def run_netscan_interactive():
    target = input("\nEnter target IP or hostname (e.g., 192.168.1.1, google.com): ")
    ports_input = input("Enter ports to scan (comma-separated, e.g., 80,443,22) or 'all' for 1-1024: ")
    
    if ports_input.lower() == 'all':
        ports = list(range(1, 1025))
    else:
        try:
            ports = [int(p.strip()) for p in ports_input.split(',')]
        except ValueError:
            print("Invalid port format. Using default ports 80, 443.")
            ports = [80, 443]

    print(f"\n[*] Starting network scan on {target}...")
    results = run_network_scan(target, ports)
    
    # Process results immediately
    print("\n--- Scan Results ---")
    if not results.get('open_ports'):
        print("No open ports found.")
    else:
        for p in results['open_ports']:
            print(f"Open Port: {p['port']}/{p['protocol']} - {p['service']} ({p['product']} {p['version']})")

    handle_reporting(results)

def run_vulnscan_interactive():
    target = input("\nEnter target URL (e.g., http://example.com): ")
    
    print(f"\n[*] Starting web vulnerability scan on {target}...")
    
    all_findings = []
    
    print("[-] Checking for SQL Injection...")
    all_findings.extend(check_sql_injection(target))
    
    print("[-] Checking for XSS...")
    all_findings.extend(check_xss(target))
    
    print("[-] Checking for Sensitive Files...")
    all_findings.extend(check_sensitive_files(target))

    print("[-] Checking for Directory Traversal...")
    all_findings.extend(check_directory_traversal(target))
    
    print("[-] Checking for Insecure Headers...")
    all_findings.extend(check_insecure_headers(target))
    
    results = {
        "target": target,
        "scan_type": "Web Vulnerability Scan",
        "vulnerabilities": all_findings
    }
    
    print("\n--- Scan Results ---")
    if not all_findings:
        print("No vulnerabilities found.")
    else:
        print(f"Found {len(all_findings)} issues.")
        for f in all_findings:
            print(f"- {f.get('type')}: {f.get('url')}")
            
    handle_reporting(results)

def run_depscan_interactive():
    path = input("\nEnter path to project directory or requirements.txt: ")
    print(f"\n[*] Starting dependency scan on {path}...")
    results = scan_dependencies(path)
    
    print("\n--- Scan Results ---")
    vulns = results.get('vulnerabilities', [])
    if not vulns:
        print("No vulnerable dependencies found.")
    else:
        print(f"Found {len(vulns)} vulnerabilities.")
        for v in vulns:
            print(f"- {v['package_name']} {v['version']}: {v['vuln_id']}")
            
    handle_reporting(results)

def run_secretscan_interactive():
    path = input("\nEnter path to file or directory to scan for secrets: ")
    print(f"\n[*] Starting secrets scan on {path}...")
    results = scan_secrets(path)
    
    # Reporting is handled inside scan_secrets somewhat, but we wrap it here
    handle_reporting(results)

def display_help():
    print("\n" + "="*50)
    print("      THREAT SCOPE - USAGE GUIDE")
    print("="*50)
    print("\n1. Network Scan (netscan)")
    print("   Scans for open ports on a target IP or hostname.")
    print("   - Target: 192.168.1.1 or scanme.nmap.org")
    print("   - Ports: '80,443' or 'all'")

    print("\n2. Web Vulnerability Scan (vulnscan)")
    print("   Checks websites for SQLi, XSS, and security headers.")
    print("   - Target: Full URL (e.g., http://example.com)")

    print("\n3. Dependency Scan (dep_scan)")
    print("   Checks 'requirements.txt' for known vulnerable libraries.")
    print("   - Path: Folder or file path (e.g., /app/requirements.txt)")

    print("\n4. Secret Scan (secret_scan)")
    print("   Scans code matching patterns like API keys or passwords.")
    print("   - Path: Folder or file path to code.")

    input("\nPress Enter to return to the main menu...")

def get_save_path(default_filename):
    print("\nWhere do you want to save the report?")
    print("1. Current Directory")
    print("2. Desktop")
    print("3. Downloads")
    print("4. Custom Path")
    
    choice = input("Enter choice (1-4): ")
    directory = "."
    
    home = os.path.expanduser("~")
    
    if choice == '1':
        directory = "."
    elif choice == '2':
        directory = os.path.join(home, "Desktop")
    elif choice == '3':
        directory = os.path.join(home, "Downloads")
    elif choice == '4':
        directory = input("Enter custom directory path: ")
    else:
        print("Invalid choice. Using current directory.")
    
    # Ensure directory exists
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
            print(f"[*] Created directory: {directory}")
        except OSError as e:
            print(f"[!] Error creating directory: {e}. Using current directory.")
            directory = "."

    filename = input(f"Enter filename (default: {default_filename}): ") or default_filename
    return os.path.join(directory, filename)

def handle_reporting(results):
    while True:
        print("\n--- Reporting Options ---")
        print("1. Generate HTML Report")
        print("2. Generate PDF Report")
        print("3. Generate Executive Note (Text)")
        print("4. Return to Main Menu")
        choice = input("Enter choice (1-4): ")
        
        if choice == '1':
            filepath = get_save_path("report.html")
            generate_html_report(results, filepath)
        elif choice == '2':
            filepath = get_save_path("report.pdf")
            generate_pdf_report(results, filepath)
        elif choice == '3':
            filepath = get_save_path("executive_note.txt")
            generate_advice_report(results, filepath)
        elif choice == '4':
            break
        else:
            print("Invalid choice.")

def main():
    while True:
        display_banner()
        print("\n--- Choose a Scan Type ---")
        print("1. Network Scan (netscan)")
        print("2. Web Vulnerability Scan (vulnscan)")
        print("3. Dependency Scan (dep_scan)")
        print("4. Secret Scan (secret_scan)")
        print("5. Help / Usage Guide")
        print("6. Exit")
        
        choice = input("Enter your choice (1-6): ")
        
        if choice == '1':
            run_netscan_interactive()
        elif choice == '2':
            run_vulnscan_interactive()
        elif choice == '3':
            run_depscan_interactive()
        elif choice == '4':
            run_secretscan_interactive()
        elif choice == '5':
            display_help()
        elif choice == '6':
            print("Exiting Threat Scope. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 6.")

if __name__ == "__main__":
    main()
