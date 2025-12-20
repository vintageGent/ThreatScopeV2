import datetime
import html
from weasyprint import HTML

# --- Remediation Advice Database ---
REMEDIATION_ADVICE = {
    "DEFAULT": {
        "title": "General Best Practices",
        "advice": "Always keep software and dependencies up to date. Regularly review code for security issues and follow the principle of least privilege."
    },
    "Network Scan": {
        "title": "Open Network Port",
        "advice": ("What it is: A network port is a communication endpoint. An 'open' port means a service is actively listening for connections, making it a potential entry point for attackers. "
                   "While many ports need to be open for legitimate services (like port 80 for a web server), unnecessary open ports increase the attack surface.\n\n"
                   "How to fix it: Review each open port. If it is not required for the server's function, you should block it using a firewall. "
                   "Ensure your firewall rules follow a 'deny by default' policy, only allowing traffic to specific, necessary ports.")
    },
    "Dependency Scan": {
        "title": "Vulnerable Dependency",
        "advice": ("What it is: Your project is using a third-party library with a known security vulnerability. "
                   "Attackers can exploit these flaws to compromise your application.\n\n"
                   "How to fix it: The best solution is to update the library to the latest stable version. "
                   "In your dependency file (e.g., requirements.txt), change the version number for the vulnerable package to a newer one and reinstall your dependencies. "
                   "For example, change 'requests==2.19.0' to 'requests>=2.31.0'.")
    },
    "Secrets Scan": {
        "title": "Hardcoded Secret",
        "advice": ("What it is: A secret, like an API key or password, has been written directly into the source code. "
                   "If the code is ever made public (e.g., on GitHub), attackers can easily find and use these secrets to gain unauthorized access to your accounts and services.\n\n"
                   "How to fix it: Remove the secret from the code. Instead, load it from a secure location at runtime. "
                   "Common methods include using environment variables or a dedicated secrets management service (like AWS Secrets Manager or HashiCorp Vault).")
    },
    "SQL Injection": {
        "title": "SQL Injection",
        "advice": ("What it is: The application allows an attacker to interfere with the database queries it makes. "
                   "This can be used to steal, modify, or delete sensitive data.\n\n"
                   "How to fix it: Use 'prepared statements' (also known as parameterized queries) in your code. "
                   "This method separates the database command from the user-provided data, ensuring the data cannot be misinterpreted as a command.")
    },
    "Cross-Site Scripting (XSS)": {
        "title": "Cross-Site Scripting (XSS)",
        "advice": ("What it is: The application allows an attacker to inject malicious scripts into web pages viewed by other users. "
                   "This can be used to steal user sessions, deface websites, or redirect users to malicious sites.\n\n"
                   "How to fix it: Implement 'output encoding'. Before displaying any user-provided data on a web page, "
                   "ensure it is properly encoded (e.g., converting '<' to '&lt;'). This tells the browser to treat the data as text, not as runnable code.")
    },
    "Sensitive File Exposure": {
        "title": "Sensitive File Exposure",
        "advice": ("What it is: A sensitive file or directory (like '.git', '.env', or a configuration file) is publicly accessible on your web server. "
                   "These files can contain secrets, source code, or other information an attacker can use.\n\n"
                   "How to fix it: Configure your web server (e.g., Nginx, Apache) to deny all public requests for these sensitive files and directories. "
                   "Ensure they are not part of your web root or have explicit 'deny all' rules applied.")
    },
    "Missing Security Header": {
        "title": "Missing Security Header",
        "advice": ("What it is: Your web server is not sending recommended HTTP security headers. These headers instruct browsers to enable built-in security features, "
                   "protecting users from common attacks like clickjacking and cross-site scripting.\n\n"
                   "How to fix it: Configure your web server or application to add the missing security headers to all outgoing responses. "
                   "For example, adding 'X-Frame-Options: DENY' helps prevent clickjacking.")
    }
}


def _generate_html_content(scan_results):
    """
    A helper function to generate the HTML content string for a report.
    This is used by both HTML and PDF generation to ensure consistency.
    """
    scan_type = scan_results.get('scan_type', 'Unknown')
    
    # --- Result Generation ---
    results_html = ""
    total_findings = 0

    if scan_type == "Dependency Scan":
        findings = scan_results.get('vulnerabilities', [])
        total_findings = len(findings)
        if not findings:
            results_html = "<h3>No vulnerable dependencies found.</h3>"
        else:
            for vuln in findings:
                severity = vuln.get('severity', 'UNKNOWN').upper()
                results_html += f"""
                <div class=\"vulnerability\">
                    <p class=\"vuln-title\">{html.escape(vuln['package_name'])}@{html.escape(vuln['version'])} - {html.escape(vuln['vuln_id'])}</p>
                    <div class=\"vuln-details\">
                        <p><strong>Severity:</strong> {html.escape(severity)}</p>
                        <p><strong>Summary:</strong> {html.escape(vuln['summary'])}</p>
                        <p><strong>Aliases:</strong> {html.escape(', '.join(vuln.get('aliases', [])))}</p>
                    </div>
                </div>
                """
    elif scan_type == "Secrets Scan":
        findings = scan_results.get('secrets', [])
        total_findings = len(findings)
        if not findings:
            results_html = "<h3>No secrets found.</h3>"
        else:
            for secret in findings:
                results_html += f"""
                <div class=\"vulnerability\">
                    <p class=\"vuln-title\">Potential {html.escape(secret['type'])} found</p>
                    <div class=\"vuln-details\">
                        <p><strong>File:</strong> {html.escape(secret['file_path'])}</p>
                        <p><strong>Line:</strong> {secret['line']}</p>
                        <p><strong>Matched Text:</strong> <code>{html.escape(secret['match'])}</code></p>
                    </div>
                </div>
                """
    elif scan_type == "Web Vulnerability Scan":
        findings = scan_results.get('vulnerabilities', [])
        total_findings = len(findings)
        if not findings:
            results_html = "<h3>No web vulnerabilities found.</h3>"
        else:
            for vuln in findings:
                results_html += f"""
                <div class=\"vulnerability\">
                    <p class=\"vuln-title\">{html.escape(vuln['type'])}</p>
                    <div class=\"vuln-details\">
                        <p><strong>URL:</strong> {html.escape(vuln['url'])}</p>
                        <p><strong>Details:</strong> {html.escape(vuln['details'])}</p>
                    </div>
                </div>
                """
    elif scan_type == "Network Scan":
        findings = scan_results.get('open_ports', [])
        total_findings = len(findings)
        if not findings:
            results_html = "<h3>No open ports found.</h3>"
        else:
            for port_info in findings:
                service_info = f"{port_info['service']} ({port_info['product']} {port_info['version']})".strip()
                results_html += f"""
                <div class=\"vulnerability\">
                    <p class=\"vuln-title\">Open Port: {port_info['ip_address']}:{port_info['port']}</p>
                    <div class=\"vuln-details\">
                        <p><strong>Protocol:</strong> {port_info['protocol']}</p>
                        <p><strong>Service:</strong> {html.escape(service_info)}</p>
                    </div>
                </div>
                """
    else:
        results_html = "<h3>Unsupported scan type for reporting.</h3>"

    # Basic HTML structure with inline CSS
    html_template = f"""
<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>ThreatScopeV2 Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f9; color: #333; }}
        .container {{ background-color: #fff; border: 1px solid #ddd; padding: 20px; border-radius: 5px; }}
        h1, h2 {{ color: #444; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }}
        .summary {{ margin-bottom: 20px; }}
        .vulnerability {{ border: 1px solid #eee; padding: 15px; margin-bottom: 15px; border-radius: 5px; background-color: #fafafa; page-break-inside: avoid; }}
        .vuln-title {{ font-size: 1.2em; font-weight: bold; color: #d9534f; }}
        .vuln-details {{ margin-top: 10px; }}
        .vuln-details p {{ margin: 5px 0; }}
        .vuln-details strong {{ color: #555; }}
        code {{ background-color: #eef; padding: 2px 5px; border-radius: 3px; }}
        .footer {{ text-align: center; margin-top: 20px; font-size: 0.9em; color: #777; }}
    </style>
</head>
<body>
    <div class=\"container\">
        <h1>ThreatScopeV2 Scan Report</h1>
        <div class=\"summary\">
            <p><strong>Scan Type:</strong> {html.escape(scan_type)}</p>
            <p><strong>Target:</strong> {html.escape(scan_results.get('target', 'Unknown'))}</p>
            <p><strong>Scan Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>Total Findings:</strong> {total_findings}</p>
        </div>

        <h2>Detailed Results</h2>
        <div class=\"results\">
            {results_html}
        </div>
    </div>
    <div class=\"footer\">
        <p>Report generated by ThreatScopeV2</p>
    </div>
</body>
</html>
"""
    return html_template

def generate_html_report(scan_results, output_file):
    """
    Generates and saves an HTML report from scan results.
    """
    html_content = _generate_html_content(scan_results)
    try:
        with open(output_file, 'w') as f:
            f.write(html_content)
        print(f"\n[+] HTML report successfully saved to {output_file}")
    except IOError as e:
        print(f"\n[!] Error saving HTML report: {e}")

def generate_pdf_report(scan_results, output_file):
    """
    Generates and saves a PDF report from scan results.
    """
    html_content = _generate_html_content(scan_results)
    try:
        HTML(string=html_content).write_pdf(output_file)
        print(f"\n[+] PDF report successfully saved to {output_file}")
    except Exception as e:
        print(f"\n[!] Error saving PDF report: {e}")

def generate_advice_report(scan_results, output_file):
    """
    Generates a text file with remediation advice for the findings.
    """
    scan_type = scan_results.get('scan_type', 'Unknown')
    
    # Determine the list of findings based on scan type
    findings = []
    if scan_type == "Network Scan":
        findings = scan_results.get('open_ports', [])
    else:
        findings = scan_results.get('vulnerabilities', []) or scan_results.get('secrets', [])

    advice_content = f"--- Remediation Advice for {scan_type} on {scan_results.get('target')} ---\n\n"
    
    if not findings:
        advice_content += "No findings to report. Keep up the great work on security!\n"
    else:
        unique_advice_types = set()
        if scan_type == "Dependency Scan":
            unique_advice_types.add("Dependency Scan")
        elif scan_type == "Secrets Scan":
            unique_advice_types.add("Secrets Scan")
        elif scan_type == "Web Vulnerability Scan":
            for finding in findings:
                unique_advice_types.add(finding['type'])
        elif scan_type == "Network Scan":
            if findings: # If there are any open ports
                unique_advice_types.add("Network Scan")

        for advice_type in sorted(list(unique_advice_types)):
            advice = REMEDIATION_ADVICE.get(advice_type, REMEDIATION_ADVICE["DEFAULT"])
            advice_content += f"--- ADVICE FOR: {advice['title']} ---\n\n"
            advice_content += f"{advice['advice']}\n\n"
            advice_content += "-------------------------------------------------\n\n"

    try:
        with open(output_file, 'w') as f:
            f.write(advice_content)
        print(f"[+] Remediation advice successfully saved to {output_file}")
    except IOError as e:
        print(f"[!] Error saving advice report: {e}")