#!/home/seeker/ThreatScopeV2/venv/bin/python3

import argparse
from urllib.parse import urlparse
from modules.network import run_network_scan
from modules.vuln_scanners import check_sql_injection, check_xss, check_sensitive_files, check_directory_traversal, check_insecure_headers
from modules.dependency_scanner import scan_dependencies
from modules.secrets_scanner import scan_secrets
from modules.reporter import generate_html_report, generate_pdf_report, generate_advice_report

def main():
    parser = argparse.ArgumentParser(description="ThreatScopeV2: A focused network and vulnerability scanner.")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # --- Parent parser for common reporting options ---
    report_parser = argparse.ArgumentParser(add_help=False)
    report_parser.add_argument('--html', help='Optional: Specify an HTML file to save the report.')
    report_parser.add_argument('--pdf', help='Optional: Specify a PDF file to save the report.')
    report_parser.add_argument('--advice', help='Optional: Specify a text file to save remediation advice.')

    # --- Network Scan Command ---
    net_parser = subparsers.add_parser('netscan', help='Run a network scan for open ports and services.', parents=[report_parser])
    net_parser.add_argument('target', help='The IP address or range to scan (e.g., 192.168.1.0/24).')
    net_parser.add_argument('--ports', help='Comma-separated list of ports to scan (e.g., 80,443).')

    # --- Vulnerability Scan Command ---
    vuln_parser = subparsers.add_parser('vulnscan', help='Scan a URL for common web vulnerabilities.', parents=[report_parser])
    vuln_parser.add_argument('url', help='The URL to scan for vulnerabilities.')

    # --- Dependency Scan Command ---
    dep_parser = subparsers.add_parser('dep_scan', help='Scan a dependency file for known vulnerabilities.', parents=[report_parser])
    dep_parser.add_argument('file', help='Path to the dependency file (e.g., requirements.txt).')

    # --- Secrets Scan Command ---
    secret_parser = subparsers.add_parser('secret_scan', help='Scan a file or directory for hardcoded secrets.', parents=[report_parser])
    secret_parser.add_argument('path', help='Path to the file or directory to scan.')

    args = parser.parse_args()

    scan_results = None

    if args.command == 'netscan':
        print(f"\n--- Network Scan ---")
        port_list = [int(p) for p in args.ports.split(',')] if args.ports else None
        scan_results = run_network_scan(args.target, port_list)
        
    elif args.command == 'vulnscan':
        print(f"\n--- Web Vulnerability Scan ---")
        print(f"[*] Target URL: {args.url}\n")
        
        all_findings = []
        all_findings.extend(check_sql_injection(args.url))
        all_findings.extend(check_xss(args.url))
        all_findings.extend(check_sensitive_files(args.url))
        all_findings.extend(check_directory_traversal(args.url))
        all_findings.extend(check_insecure_headers(args.url))

        scan_results = {
            "target": args.url,
            "scan_type": "Web Vulnerability Scan",
            "vulnerabilities": all_findings
        }

        if not all_findings:
            print("\n[+] No web vulnerabilities found.")
        else:
            print(f"\n[!] Scan complete. Found {len(all_findings)} potential web vulnerability/ies.")
            for finding in all_findings:
                print(f"  [!] {finding['type']} found at {finding['url']}")
                print(f"    - Details: {finding['details']}")
                print("-" * 20)

    elif args.command == 'dep_scan':
        scan_results = scan_dependencies(args.file)
            
    elif args.command == 'secret_scan':
        scan_results = scan_secrets(args.path)

    else:
        parser.print_help()

    # --- Reporting ---
    if scan_results:
        if args.html:
            generate_html_report(scan_results, args.html)
        if args.pdf:
            generate_pdf_report(scan_results, args.pdf)
        if args.advice:
            generate_advice_report(scan_results, args.advice)


if __name__ == "__main__":
    main()